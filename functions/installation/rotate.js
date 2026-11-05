import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { suspendedInstallation } from "../_shared/mail-nonce.js";
import { verifyInstallationProof } from "../_shared/installation-proof.js";

const idPattern = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_REGISTRATION_LIMIT)
    return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_REGISTRATION_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const oldProof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  const newProof = await verifyInstallationProof(request.headers.get("Kautuka-Replacement-Proof"), request, env.BROKER_ORIGIN);
  if (!oldProof || !newProof || oldProof.thumbprint === newProof.thumbprint) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "id,operationId,replacementThumbprint"
    || !idPattern.test(body.id ?? "") || !idPattern.test(body.operationId ?? "") || body.replacementThumbprint !== newProof.thumbprint)
    return new Response("rejected", { status: 400, headers });
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/rotate", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ oldProof, newProof, operationId: body.operationId }),
    });
    if (response.status === 423) return suspendedInstallation();
    return new Response(null, { status: response.ok ? 204 : response.status === 409 ? 409 : 503, headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
