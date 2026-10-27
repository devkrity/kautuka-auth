import { issueTicket, validReturn } from "../_shared/ticket.js";

const connectors = new Set([
  "kautuka-google-mail",
  "kautuka-m365-mail",
  "kautuka-login-google",
  "kautuka-login-microsoft",
]);
const pkcePattern = /^[A-Za-z0-9_-]{43,128}$/;

export async function onRequestPost({ request, env }) {
  const requestUrl = new URL(request.url);
  const origin = request.headers.get("origin");
  if (origin !== requestUrl.origin) return rejected();
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin") return rejected();
  if (request.headers.get("content-type")?.split(";")[0] !== "application/json") return rejected();
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 8192) return rejected();

  let input;
  try {
    const body = await request.text();
    if (body.length > 8192) return rejected();
    input = JSON.parse(body);
  } catch {
    return rejected();
  }

  const { returnUrl, connector, state, challenge, nonce, microsoftAccountType } = input ?? {};
  const validAccountType = microsoftAccountType == null
    || connector === "kautuka-login-microsoft" && ["organizations", "consumers"].includes(microsoftAccountType);
  if (!connectors.has(connector)
    || !validReturn(returnUrl, connector)
    || !pkcePattern.test(state ?? "")
    || !pkcePattern.test(challenge ?? "")
    || connector.startsWith("kautuka-login-") && !pkcePattern.test(nonce ?? "")
    || !validAccountType) return rejected();
  if (typeof env.AUTH_TICKET_HMAC_KEY !== "string" || env.AUTH_TICKET_HMAC_KEY.length < 32) {
    return new Response("not configured", { status: 503, headers: noStore() });
  }

  const ticket = await issueTicket(env, {
    aud: requestUrl.origin,
    returnUrl,
    connector,
    state,
    challenge,
    nonce: nonce ?? "",
    microsoftAccountType: microsoftAccountType ?? "",
  });
  return Response.json({ ticket }, { headers: { "cache-control": "no-store" } });
}

function rejected() {
  return new Response("rejected", { status: 400, headers: noStore() });
}

function noStore() {
  return { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" };
}

