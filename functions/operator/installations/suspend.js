import { readBoundedBody } from "../../_shared/installation-proof.js";

const id = /^[A-Za-z0-9_-]{43}$/;
const secretPattern = /^[A-Za-z0-9_-]{43,128}$/;
const encoder = new TextEncoder();

// This is a CLI-only control. It does not accept browser cookies or CORS.
export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  const secret = env.OPERATOR_SUSPEND_SECRET;
  const operatorId = env.OPERATOR_SUSPEND_CREDENTIAL_ID;
  if (!secretPattern.test(secret ?? "") || !/^[A-Za-z0-9_.-]{1,64}$/.test(operatorId ?? "")
    || !env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.INSTALLATION_CONTROL_LIMIT)
    return new Response("not configured", { status: 503, headers });
  if (new URL(request.url).origin !== env.BROKER_ORIGIN || request.headers.has("origin")
    || request.headers.get("content-type") !== "application/json") return new Response("rejected", { status: 403, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.INSTALLATION_CONTROL_LIMIT.limit({ key: `operator:${ip}` })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  const authorization = request.headers.get("authorization") ?? "";
  const provided = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const [expected, actual] = await Promise.all([secret, provided].map(value => crypto.subtle.digest("SHA-256", encoder.encode(value))));
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= new Uint8Array(expected)[i] ^ new Uint8Array(actual)[i];
  if (difference !== 0 || !secretPattern.test(provided)) return new Response("rejected", { status: 403, headers });
  const bytes = await readBoundedBody(request, 2048);
  let body;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "id,operationId,reason"
    || typeof body.id !== "string" || !id.test(body.id) || typeof body.operationId !== "string" || !id.test(body.operationId)
    || typeof body.reason !== "string" || !/^[a-z0-9_-]{1,64}$/.test(body.reason))
    return new Response("rejected", { status: 400, headers });
  try {
    const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`));
    const response = await object.fetch("https://installation.internal/operator-suspend", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ operationId: body.operationId, reason: body.reason, operatorId }) });
    if (response.status === 404) return new Response("not found", { status: 404, headers });
    if (!response.ok) return new Response("temporarily unavailable", { status: 503, headers });
    const result = await response.json();
    if (!["suspended", "already_suspended"].includes(result.status)) throw new Error("invalid suspension response");
    console.info("operator_installation_suspension", JSON.stringify({ id: body.id, operationId: body.operationId, reason: body.reason, operatorId, status: result.status }));
    return Response.json(result, { headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
