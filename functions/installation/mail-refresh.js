import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof, readBoundedBody } from "../_shared/installation-proof.js";
import { verifyDpop } from "../_shared/mail-token.js";
import { isKeyringReady, openMailFlowResult, sealMailFlowResult } from "../_shared/token-state.js";
import { hasRequiredMailScopes } from "../_shared/mail-scopes.js";

const identifier = /^[A-Za-z0-9_-]{43}$/;
const configs = {
  google: { client: "GOOGLE_CLIENT_ID", secret: "GOOGLE_CLIENT_SECRET", endpoint: "https://oauth2.googleapis.com/token" },
  microsoft: { client: "MICROSOFT_CLIENT_ID", secret: "MICROSOFT_CLIENT_SECRET", endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token" },
};
const digest = async (value) => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))))
  .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.MAIL_REFRESH_LIMIT || !isKeyringReady(env))
    return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.MAIL_REFRESH_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  const dpop = await verifyDpop(request.headers.get("DPoP"), "refresh_token", null, { htm: "POST", htu: `${env.BROKER_ORIGIN}/installation/mail-refresh` });
  if (!proof || !dpop.ok) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body)
    || Object.keys(body).sort().join(",") !== "connectionId,flowId,generation,id,operationId,provider,refreshToken"
    || ![body.id, body.flowId, body.connectionId, body.operationId].every((v) => typeof v === "string" && identifier.test(v))
    || !Object.hasOwn(configs, body.provider) || !Number.isSafeInteger(body.generation) || body.generation < 1
    || typeof body.refreshToken !== "string" || !body.refreshToken.startsWith("kmf1.") || body.refreshToken.length > 12000)
    return new Response("rejected", { status: 400, headers });
  const config = configs[body.provider];
  if (!env[config.client] || !env[config.secret]) return new Response("not configured", { status: 503, headers });
  const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`));
  const input = { provider: body.provider, connection: body.connectionId, flowId: body.flowId, generation: body.generation,
    operationId: body.operationId, credentialHash: await digest(body.refreshToken), dpopJkt: dpop.jkt };
  const binding = await digest(JSON.stringify(["mail-refresh-v1", body.id, body.provider, body.connectionId, body.generation, body.flowId, dpop.jkt, body.operationId]));
  const invoke = (path, value) => object.fetch(`https://installation.internal/${path}`, { method: "POST",
    headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
  try {
    const dpopFingerprint = await digest(JSON.stringify([dpop.jkt, dpop.jti]));
    const claim = await invoke("claim-mail-refresh", { ...input, dpopFingerprint, thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt });
    if (claim.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    if (!claim.ok) return new Response(null, { status: 503, headers });
    let result = await claim.json();
    if (result.status === "busy") return new Response(null, { status: 202, headers });
    if (result.status === "unknown") return new Response("Reconnect the mail account.", { status: 410, headers });
    if (result.status === "insufficient_scope") return new Response("Required mail permissions were not granted.", {
      status: 403, headers: { ...headers, "kautuka-mail-error": "insufficient_scope" },
    });
    if (result.status === "invalid") return new Response("rejected", { status: 409, headers });
    if (result.status === "claimed") {
      const refreshToken = await openMailFlowResult(env, body.id, body.flowId, dpop.jkt, body.refreshToken);
      if (!refreshToken) throw new Error("invalid credential");
      const form = new URLSearchParams({ client_id: env[config.client], client_secret: env[config.secret], grant_type: "refresh_token", refresh_token: refreshToken });
      const upstream = await fetch(config.endpoint, { method: "POST", redirect: "manual", signal: AbortSignal.timeout(15000),
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: form });
      if (!upstream.ok) throw new Error("provider rejected");
      const bytes = await readBoundedBody(upstream, 32768);
      if (!bytes) throw new Error("oversized provider response");
      const token = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (typeof token.access_token !== "string" || !token.access_token || token.access_token.length > 20000
        || token.refresh_token != null && (typeof token.refresh_token !== "string" || !token.refresh_token || token.refresh_token.length > 8192)) throw new Error("invalid provider response");
      if (token.scope !== undefined && !hasRequiredMailScopes(body.provider, token.scope)) {
        const failed = await invoke("fail-mail-refresh-scope", input);
        if (!failed.ok) return new Response("Mail connection is no longer available.", { status: 409, headers });
        return new Response("Required mail permissions were not granted.", {
          status: 403, headers: { ...headers, "kautuka-mail-error": "insufficient_scope" },
        });
      }
      const nextCredentialEnvelope = await sealMailFlowResult(env, body.id, body.flowId, dpop.jkt, token.refresh_token ?? refreshToken);
      const nextCredentialHash = await digest(nextCredentialEnvelope);
      const issuedAt = Date.now();
      const payload = { accessToken: token.access_token, refreshToken: nextCredentialEnvelope, issuedAt,
        tokenType: typeof token.token_type === "string" ? token.token_type : "Bearer",
        expiresAt: typeof token.expires_in === "number" && Number.isFinite(token.expires_in) && token.expires_in > 0
          ? issuedAt + Math.min(token.expires_in, 86400) * 1000 : null };
      const sealedResult = await sealMailFlowResult(env, body.id, binding, dpop.jkt, JSON.stringify(payload));
      const finished = await invoke("finish-mail-refresh", { ...input, nextCredentialHash, nextCredentialEnvelope, sealedResult });
      if (!finished.ok) return new Response("Mail connection is no longer available.", { status: 409, headers });
      const saved = await invoke("read-mail-refresh", input);
      if (!saved.ok) return new Response("Mail connection is no longer available.", { status: 409, headers });
      result = { status: "complete", ...(await saved.json()) };
    }
    if (result.status !== "complete") return new Response("rejected", { status: 409, headers });
    const plaintext = await openMailFlowResult(env, body.id, binding, dpop.jkt, result.sealedResult);
    return plaintext ? Response.json(JSON.parse(plaintext), { headers }) : new Response("temporarily unavailable", { status: 503, headers });
  } catch { return new Response("Mail refresh could not be completed. Retry the same operation.", { status: 503, headers }); }
}
