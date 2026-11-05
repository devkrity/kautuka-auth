import { mailNonceChallenge } from "../_shared/mail-nonce.js";
import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof, readBoundedBody, dpopReplayFingerprint } from "../_shared/installation-proof.js";
import { verifyDpop } from "../_shared/mail-token.js";
import { isMailIdentityConfigured, resolveMailAccount } from "../_shared/mail-identity.js";
import { hasRequiredMailScopes } from "../_shared/mail-scopes.js";
import { isKeyringReady, openMailFlowResult, sealMailFlowResult } from "../_shared/token-state.js";

const id = /^[A-Za-z0-9_-]{43}$/;
const verifier = /^[A-Za-z0-9._~-]{43,128}$/;
const providers = {
  google: { client: "GOOGLE_CLIENT_ID", secret: "GOOGLE_CLIENT_SECRET", endpoint: "https://oauth2.googleapis.com/token", route: "google-mail" },
  microsoft: { client: "MICROSOFT_CLIENT_ID", secret: "MICROSOFT_CLIENT_SECRET", endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token", route: "microsoft-mail" },
};

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_POLL_LIMIT
    || !isKeyringReady(env) || !isMailIdentityConfigured(env)) return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_POLL_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  const dpop = await verifyDpop(request.headers.get("DPoP"), "authorization_code", null, { htm: "POST", htu: `${env.BROKER_ORIGIN}/installation/mail-exchange` });
  if (!proof || !dpop.ok) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id,verifier"
    || typeof body.id !== "string" || !id.test(body.id) || typeof body.flowId !== "string" || !id.test(body.flowId)
    || typeof body.verifier !== "string" || !verifier.test(body.verifier)) return new Response("rejected", { status: 400, headers });
  const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`));
  const binding = { flowId: body.flowId, verifier: body.verifier, dpopJkt: dpop.jkt };
  const invoke = (path, data) => object.fetch(`https://installation.internal/${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data),
  });
  try {
    const allowedProviders = Object.entries(providers).filter(([, config]) => env[config.client] && env[config.secret]).map(([name]) => name);
    const response = await invoke("claim-mail-exchange", { ...binding, allowedProviders, dpopFingerprint: await dpopReplayFingerprint(dpop),
      dpopNonce: dpop.nonce, thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt });
    const nonceChallenge = mailNonceChallenge(response);
    if (nonceChallenge) return nonceChallenge;
    if (response.status === 202) return new Response(null, { status: 202, headers });
    if (response.status === 429) {
      const denied = await response.json();
      if (denied.code !== "new_account_limit" || !Number.isSafeInteger(denied.retryAt)) throw new Error("invalid admission denial");
      return Response.json(denied, { status: 429, headers: { ...headers, "kautuka-admission-denied": "new_account_limit", "retry-after": String(Math.max(1, Math.ceil((denied.retryAt - Date.now()) / 1000))) } });
    }
    if (response.status === 409) {
      let denied;
      try { denied = await response.json(); } catch { /* Other conflicts have no body. */ }
      if (denied?.code === "active_account_limit")
        return new Response(null, { status: 409, headers: { ...headers, "kautuka-admission-denied": "active_account_limit" } });
      return new Response(null, { status: 409, headers });
    }
    if (response.status === 403) {
      let rejected;
      try { rejected = await response.json(); } catch { /* Invalid proof has no response body. */ }
      if (rejected?.code === "insufficient_scope") return new Response("Required mail permissions were not granted.", {
        status: 403, headers: { ...headers, "kautuka-mail-error": "insufficient_scope" },
      });
      return rejectInvalidProof(env, ip, headers, 403);
    }
    if (!response.ok) return new Response(null, { status: [202, 409, 410].includes(response.status) ? response.status : 503, headers });
    let claimed = await response.json();
    if (!claimed.sealedResult) {
      const config = providers[claimed.claim?.provider];
      if (!config || !env[config.client] || !env[config.secret] || claimed.claim?.purpose !== "mail") throw new Error("invalid claim");
      const form = new URLSearchParams({ client_id: env[config.client], client_secret: env[config.secret], grant_type: "authorization_code",
        code: claimed.claim.code, code_verifier: body.verifier, redirect_uri: `${env.BROKER_ORIGIN}/callback` });
      const upstream = await fetch(config.endpoint, { method: "POST", redirect: "manual", signal: AbortSignal.timeout(15000),
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: form });
      if (!upstream.ok) throw new Error("provider rejected");
      const bytes = await readBoundedBody(upstream, 32768);
      if (!bytes) throw new Error("oversized response");
      const token = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (typeof token.access_token !== "string" || !token.access_token || typeof token.refresh_token !== "string" || !token.refresh_token)
        throw new Error("missing credentials");
      if (!hasRequiredMailScopes(claimed.claim.provider, token.scope)) {
        const failed = await invoke("fail-exchange-scope", { flowId: body.flowId });
        if (!failed.ok) throw new Error("could not close insufficient-scope flow");
        return new Response("Required mail permissions were not granted.", {
          status: 403, headers: { ...headers, "kautuka-mail-error": "insufficient_scope" },
        });
      }
      const account = await resolveMailAccount(env, claimed.claim.provider, body.id, token.access_token);
      if (!account) throw new Error("identity unavailable");
      // A provisional envelope must never be accepted by the legacy refresh
      // endpoint. The new refresh path must verify active generation first.
      const wrapped = await sealMailFlowResult(env, body.id, body.flowId, dpop.jkt, token.refresh_token);
      const hashBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(wrapped)));
      const credentialHash = btoa(String.fromCharCode(...hashBytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
      const sealedResult = await sealMailFlowResult(env, body.id, body.flowId, dpop.jkt, JSON.stringify({ refreshToken: wrapped, provider: claimed.claim.provider }));
      const result = await invoke("finish-mail-exchange", { flowId: body.flowId, account, sealedResult, credentialHash, credentialEnvelope: wrapped });
      if (result.status === 429) {
        const denied = await result.json();
        if (denied.error !== "new_account_limit" || !Number.isSafeInteger(denied.retryAt)) throw new Error("invalid admission denial");
        return Response.json({ code: denied.error, retryAt: denied.retryAt, restartRequired: true }, { status: 429,
          headers: { ...headers, "kautuka-admission-denied": "new_account_limit", "retry-after": String(Math.max(1, Math.ceil((denied.retryAt - Date.now()) / 1000))) } });
      }
      if (result.status === 409) {
        let denied;
        try { denied = await result.json(); } catch { /* Other conflicts have no body. */ }
        if (denied?.error === "limit")
          return new Response(null, { status: 409, headers: { ...headers, "kautuka-admission-denied": "active_account_limit" } });
        return new Response("Mail connection could not be admitted.", { status: 409, headers });
      }
      if (!result.ok) return new Response("Mail connection could not be admitted.", { status: 409, headers });
      const saved = await invoke("read-mail-result", binding);
      if (!saved.ok) return new Response("Mail connection is no longer available.", { status: 409, headers });
      claimed = await saved.json();
    }
    const plaintext = await openMailFlowResult(env, body.id, body.flowId, dpop.jkt, claimed.sealedResult);
    if (!plaintext) return new Response("temporarily unavailable", { status: 503, headers });
    return Response.json({ ...JSON.parse(plaintext), generation: claimed.generation }, { headers });
  } catch {
    try { await invoke("fail-exchange", { flowId: body.flowId }); } catch { /* Lease expires closed. */ }
    return new Response("Mail sign-in could not be completed. Start again.", { status: 503, headers });
  }
}
