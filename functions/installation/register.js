import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof } from "../_shared/installation-proof.js";
import { suspendedInstallation } from "../_shared/mail-nonce.js";

const idPattern = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const noStore = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_REGISTRATION_LIMIT) {
    return new Response("not configured", { status: 503, headers: noStore });
  }
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers: noStore });
  let allowed;
  try { allowed = await env.INSTALLATION_REGISTRATION_LIMIT.limit({ key: ip }); }
  catch { return new Response("temporarily unavailable", { status: 503, headers: noStore }); }
  if (!allowed.success) return new Response("too many requests", { status: 429, headers: { ...noStore, "retry-after": "60" } });

  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  if (!proof) return rejectInvalidProof(env, ip, noStore);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers: noStore }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).join(",") !== "id"
    || typeof body.id !== "string" || !idPattern.test(body.id)) return new Response("rejected", { status: 400, headers: noStore });
  try {
    const id = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
    const response = await env.INSTALLATION_STATE.get(id).fetch("https://installation.internal/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt }),
    });
    if (response.status === 423) return suspendedInstallation();
    if (response.status === 409) return rejectInvalidProof(env, ip, noStore, 409);
    return new Response(null, { status: response.ok ? 204 : 503, headers: noStore });
  } catch {
    return new Response("temporarily unavailable", { status: 503, headers: noStore });
  }
}
