import { getExistingBrowserCookie, hashBrowserCookie } from "../_shared/browser-cookie.js";
import { readFlowReference } from "../_shared/flow-reference.js";
import { readBoundedBody } from "../_shared/installation-proof.js";

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.HANDOFF_LIMIT || !env.AUTH_TICKET_HMAC_KEY)
    return new Response("not configured", { status: 503, headers });
  if (new URL(request.url).origin !== env.BROKER_ORIGIN || request.headers.get("origin") !== env.BROKER_ORIGIN
    || request.headers.get("content-type")?.split(";")[0] !== "application/json") return new Response("rejected", { status: 400, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.HANDOFF_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  let body;
  try {
    const bytes = await readBoundedBody(request, 4096);
    if (!bytes) return new Response("rejected", { status: 400, headers });
    body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!body || typeof body !== "object" || Array.isArray(body)
      || Object.keys(body).some((key) => !["state", "code", "error"].includes(key))) return new Response("rejected", { status: 400, headers });
  } catch { return new Response("rejected", { status: 400, headers }); }
  let reference;
  try { reference = await readFlowReference(env, env.BROKER_ORIGIN, body.state); }
  catch { return new Response("rejected", { status: 400, headers }); }
  if (!reference || (typeof body.code === "string") === (typeof body.error === "string")) return new Response("rejected", { status: 400, headers });
  const cookie = getExistingBrowserCookie(request, reference.flowId);
  if (!cookie) return new Response("rejected", { status: 400, headers });
  const result = typeof body.code === "string" ? { code: body.code } : { error: body.error };
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${reference.id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/provider-callback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ flowId: reference.flowId, state: reference.state, cookieHash: await hashBrowserCookie(cookie), result }),
    });
    return new Response(null, { status: response.ok ? 204 : response.status === 409 ? 409 : 503, headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
