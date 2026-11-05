import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof } from "../_shared/installation-proof.js";

const identifier = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_CONTROL_LIMIT)
    return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_CONTROL_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  if (!proof) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id,nonce"
    || [body.id, body.flowId, body.nonce].some((value) => typeof value !== "string" || !identifier.test(value)))
    return new Response("rejected", { status: 400, headers });
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/bind-browser", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt,
        flowId: body.flowId, nonce: body.nonce }),
    });
    if (response.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    if ([204, 409].includes(response.status)) return new Response(null, { status: response.status, headers });
    return new Response("temporarily unavailable", { status: 503, headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
