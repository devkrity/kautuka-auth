import { mailNonceChallenge } from "../_shared/mail-nonce.js";
import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof } from "../_shared/installation-proof.js";
import { verifyDpop } from "../_shared/mail-token.js";

const id = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_CONTROL_LIMIT) return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_CONTROL_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  const dpop = await verifyDpop(request.headers.get("DPoP"), "refresh_token", null, { htm: "POST", htu: `${env.BROKER_ORIGIN}/installation/mail-refresh-ack` });
  if (!proof || !dpop.ok) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body)
    || Object.keys(body).sort().join(",") !== "connectionId,flowId,generation,id,operationId,provider"
    || ![body.id, body.flowId, body.connectionId, body.operationId].every((v) => typeof v === "string" && id.test(v))
    || !["google", "microsoft"].includes(body.provider) || !Number.isSafeInteger(body.generation) || body.generation < 1)
    return new Response("rejected", { status: 400, headers });
  try {
    const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`));
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([dpop.jkt, dpop.jti]))));
    const dpopFingerprint = btoa(String.fromCharCode(...hash)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const response = await object.fetch("https://installation.internal/ack-mail-refresh", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ provider: body.provider, connection: body.connectionId,
        flowId: body.flowId, generation: body.generation, operationId: body.operationId, dpopJkt: dpop.jkt,
        dpopFingerprint, dpopNonce: dpop.nonce, thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt }) });
    const nonceChallenge = mailNonceChallenge(response);
    if (nonceChallenge) return nonceChallenge;
    if (response.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    return new Response(null, { status: [204, 409].includes(response.status) ? response.status : 503, headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
