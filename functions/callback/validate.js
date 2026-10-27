import { readTicket } from "../_shared/ticket.js";

export async function onRequestPost({ request, env }) {
  const origin = new URL(request.url).origin;
  if (request.headers.get("origin") !== origin
    || request.headers.get("content-type")?.split(";")[0] !== "application/json") return rejected();
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 8192) return rejected();

  let body;
  try {
    const raw = await request.text();
    if (raw.length > 8192) return rejected();
    body = JSON.parse(raw);
  } catch {
    return rejected();
  }
  const claims = await readTicket(env, body?.ticket, origin);
  if (!claims) return rejected();
  return Response.json({ returnUrl: claims.returnUrl, connector: claims.connector, state: claims.state }, {
    headers: { "cache-control": "no-store" },
  });
}

function rejected() {
  return Response.json({ error: "rejected" }, { status: 400, headers: { "cache-control": "no-store" } });
}
