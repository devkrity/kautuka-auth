import { rejectInvalidProof } from "../_shared/invalid-proof.js";
import { verifyInstallationProof } from "../_shared/installation-proof.js";
import { isMailIdentityConfigured } from "../_shared/mail-identity.js";
import { isKeyringReady } from "../_shared/token-state.js";

const allowed = new Set(["id", "provider", "purpose", "state", "challenge", "nonce", "gatewayOrigin",
  "connectionId", "dpopJkt", "expectedGeneration", "microsoftAccountType"]);
const identifier = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_FLOW_LIMIT)
    return new Response("not configured", { status: 503, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_FLOW_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }

  const proof = await verifyInstallationProof(request.headers.get("Kautuka-Installation-Proof"), request, env.BROKER_ORIGIN);
  if (!proof) return rejectInvalidProof(env, ip, headers);
  let body;
  try { body = await request.json(); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body)
    || Object.keys(body).some((key) => !allowed.has(key))
    || typeof body.id !== "string" || !identifier.test(body.id)) return new Response("rejected", { status: 400, headers });
  if (body.purpose === "mail" && (!isMailIdentityConfigured(env) || !isKeyringReady(env)))
    return new Response("Mail sign-in is not configured.", { status: 503, headers });
  if (body.purpose === "mail" && ((body.provider === "google" && (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET))
    || (body.provider === "microsoft" && (!env.MICROSOFT_CLIENT_ID || !env.MICROSOFT_CLIENT_SECRET))))
    return new Response("Mail sign-in is not configured.", { status: 503, headers });
  const { id, ...flow } = body;
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/create-flow", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ thumbprint: proof.thumbprint, jti: proof.jti, expiresAt: proof.expiresAt, flow }),
    });
    if (response.status === 403) return rejectInvalidProof(env, ip, headers, 403);
    if (response.status === 400) return new Response("rejected", { status: 400, headers });
    if (!response.ok) return new Response("temporarily unavailable", { status: 503, headers });
    return Response.json(await response.json(), { headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
