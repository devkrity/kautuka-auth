import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { readBoundedBody, verifyInstallationProof } from "../_shared/installation-proof.js";
import { isKeyringReady, openSocialFlowResult, sealSocialFlowResult } from "../_shared/token-state.js";

const idPattern = /^[A-Za-z0-9_-]{43}$/;
const verifierPattern = /^[A-Za-z0-9._~-]{43,128}$/;
const providers = {
  google: { client: "GOOGLE_LOGIN_CLIENT_ID", secret: "GOOGLE_LOGIN_CLIENT_SECRET", endpoint: "https://oauth2.googleapis.com/token" },
  microsoft: { client: "MICROSOFT_LOGIN_CLIENT_ID", secret: "MICROSOFT_LOGIN_CLIENT_SECRET", endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token" },
};

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_POLL_LIMIT || !isKeyringReady(env))
    return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_POLL_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  if (!proof) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id,verifier"
    || typeof body.id !== "string" || !idPattern.test(body.id) || typeof body.flowId !== "string" || !idPattern.test(body.flowId)
    || typeof body.verifier !== "string" || !verifierPattern.test(body.verifier)) return new Response("rejected", { status: 400, headers });
  const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
  const object = env.INSTALLATION_STATE.get(objectId);
  let claimed;
  try {
    const response = await object.fetch("https://installation.internal/claim-social-exchange", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt,
        flowId: body.flowId, verifier: body.verifier }),
    });
    if (response.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    if (response.status === 202) return new Response(null, { status: 202, headers });
    if (response.status === 410) return new Response("Sign-in could not be completed. Start again.", { status: 410, headers });
    if (response.status === 409) return new Response("not ready", { status: 409, headers });
    if (!response.ok) return new Response("temporarily unavailable", { status: 503, headers });
    claimed = await response.json();
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  if (claimed.sealedResult) {
    const idToken = await openSocialFlowResult(env, body.id, body.flowId, claimed.sealedResult);
    return idToken ? Response.json({ id_token: idToken }, { headers }) : new Response("temporarily unavailable", { status: 503, headers });
  }
  const config = providers[claimed.claim?.provider];
  if (!config || !env[config.client] || !env[config.secret]) {
    await fail(object, body.flowId);
    return new Response("not configured", { status: 503, headers });
  }
  let exchangeStage = "provider_request";
  let providerRejected = false;
  try {
    const form = new URLSearchParams({ client_id: env[config.client], client_secret: env[config.secret], grant_type: "authorization_code",
      code: claimed.claim.code, code_verifier: body.verifier, redirect_uri: `${env.BROKER_ORIGIN}/callback` });
    const response = await fetch(config.endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: form, redirect: "manual", signal: AbortSignal.timeout(15000) });
    if (!response.ok) {
      providerRejected = true;
      console.warn("Social provider token exchange rejected", { provider: claimed.claim.provider, status: response.status });
      throw new Error("provider rejected");
    }
    exchangeStage = "provider_response";
    const responseBytes = await readBoundedBody(response, 32768);
    if (!responseBytes) throw new Error("provider response too large");
    const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(responseBytes));
    exchangeStage = "store_result";
    const sealedResult = await sealSocialFlowResult(env, body.id, body.flowId, payload.id_token);
    const finish = await object.fetch("https://installation.internal/finish-social-exchange", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ flowId: body.flowId, sealedResult }),
    });
    if (!finish.ok) throw new Error("flow no longer active");
    return Response.json({ id_token: payload.id_token }, { headers });
  } catch {
    console.warn("Social token exchange failed", { provider: claimed.claim.provider, stage: exchangeStage });
    await fail(object, body.flowId);
    return new Response("Sign-in temporarily unavailable. Retry.", { status: providerRejected ? 502 : 503, headers });
  }
}

async function fail(object, flowId) {
  try {
    await object.fetch("https://installation.internal/fail-exchange", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ flowId }) });
  } catch { /* The in-progress record fails closed until expiry. */ }
}
