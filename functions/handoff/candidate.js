import { getOrCreateBrowserCookie, hashBrowserCookie } from "../_shared/browser-cookie.js";
import { readBoundedBody } from "../_shared/installation-proof.js";

const identifier = /^[A-Za-z0-9_-]{43}$/;

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.HANDOFF_LIMIT)
    return new Response("not configured", { status: 503, headers });
  const url = new URL(request.url);
  if (url.origin !== env.BROKER_ORIGIN || request.headers.get("origin") !== env.BROKER_ORIGIN
    || request.headers.get("content-type")?.split(";")[0] !== "application/json")
    return new Response("rejected", { status: 400, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.HANDOFF_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  if (Number(request.headers.get("content-length") ?? 0) > 1024) return new Response("rejected", { status: 400, headers });
  let body;
  try {
    const bytes = await readBoundedBody(request, 1024);
    if (bytes === null) throw new Error("oversized");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    body = JSON.parse(text);
  } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id"
    || typeof body.id !== "string" || !identifier.test(body.id)
    || typeof body.flowId !== "string" || !identifier.test(body.flowId)) return new Response("rejected", { status: 400, headers });
  const cookie = getOrCreateBrowserCookie(request, body.flowId);
  if (!cookie) return new Response("rejected", { status: 400, headers });
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/browser-candidate", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ flowId: body.flowId, cookieHash: await hashBrowserCookie(cookie.value) }),
    });
    if (!response.ok) return new Response("rejected", { status: 400, headers });
    if (cookie.header) headers["set-cookie"] = cookie.header;
    return Response.json(await response.json(), { headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
