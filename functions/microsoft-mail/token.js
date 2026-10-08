const tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const scope = "offline_access Mail.ReadWrite Mail.Send User.Read";

export async function onRequestPost(context) {
  const clientId = context.env.MICROSOFT_CLIENT_ID;
  if (!clientId) {
    return text("Microsoft mail sign-in is not configured.", 503);
  }

  const redirectUri = callbackFor(context.request);
  const body = await context.request.text();
  if (!redirectUri || body.length > 8000) {
    return text("rejected", 400);
  }

  const form = new URLSearchParams(body);
  if (form.has("client_id") || form.has("client_secret")) {
    return text("rejected", 400);
  }

  const grant = form.get("grant_type");
  if (grant !== "authorization_code" && grant !== "refresh_token") {
    return text("rejected", 400);
  }

  if (grant === "authorization_code" && form.get("redirect_uri") !== redirectUri) {
    return text("rejected", 400);
  }

  const outbound = new URLSearchParams();
  outbound.set("client_id", clientId);
  outbound.set("grant_type", grant);
  outbound.set("scope", scope);
  if (grant === "authorization_code") {
    outbound.set("code", form.get("code") ?? "");
    outbound.set("code_verifier", form.get("code_verifier") ?? "");
    outbound.set("redirect_uri", redirectUri);
  } else {
    outbound.set("refresh_token", form.get("refresh_token") ?? "");
  }

  const microsoft = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: outbound,
  });
  const headers = new Headers();
  headers.set("content-type", "application/json");
  headers.set("cache-control", "no-store");
  return new Response(microsoft.body, { status: microsoft.status, headers });
}

function callbackFor(request) {
  const url = new URL(request.url);
  if (url.protocol !== "https:") {
    return null;
  }

  return `${url.origin}/callback`;
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
