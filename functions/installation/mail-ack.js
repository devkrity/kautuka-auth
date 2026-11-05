import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof, dpopReplayFingerprint } from "../_shared/installation-proof.js";
import { verifyDpop } from "../_shared/mail-token.js";

const id = /^[A-Za-z0-9_-]{43}$/;
const verifier = /^[A-Za-z0-9._~-]{43,128}$/;

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
  const dpop = await verifyDpop(request.headers.get("DPoP"), "authorization_code", null, { htm: "POST", htu: `${env.BROKER_ORIGIN}/installation/mail-ack` });
  if (!proof || !dpop.ok) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id,verifier"
    || typeof body.id !== "string" || !id.test(body.id) || typeof body.flowId !== "string" || !id.test(body.flowId)
    || typeof body.verifier !== "string" || !verifier.test(body.verifier)) return new Response("rejected", { status: 400, headers });
  try {
    const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`));
    const response = await object.fetch("https://installation.internal/ack-mail-exchange", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ flowId: body.flowId, verifier: body.verifier, dpopJkt: dpop.jkt,
        dpopFingerprint: await dpopReplayFingerprint(dpop), thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt }) });
    if (response.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    return new Response(null, { status: [204, 409].includes(response.status) ? response.status : 503, headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
