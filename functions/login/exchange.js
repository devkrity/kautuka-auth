const maxBody = 8000;

export function createLoginExchange({ clientIdEnv, clientSecretEnv, tokenEndpoint }) {
  return async function onRequestPost(context) {
    const clientId = context.env[clientIdEnv];
    const clientSecret = context.env[clientSecretEnv];
    if (!clientId || !clientSecret) {
      return text("Sign-in is not configured.", 503);
    }

    const raw = await context.request.text();
    if (raw.length > maxBody) {
      return text("rejected", 400);
    }

    const form = new URLSearchParams(raw);
    if (form.has("client_secret") || form.has("client_id")) {
      return text("rejected", 400);
    }

    const redirect = callbackFor(context.request);
    if (!redirect || form.get("grant_type") !== "authorization_code" || form.get("redirect_uri") !== redirect) {
      return text("rejected", 400);
    }

    const code = form.get("code") ?? "";
    const verifier = form.get("code_verifier") ?? "";
    if (!isBounded(code, 2048) || !isBounded(verifier, 256)) {
      return text("rejected", 400);
    }

    const outbound = new URLSearchParams();
    outbound.set("client_id", clientId);
    outbound.set("client_secret", clientSecret);
    outbound.set("grant_type", "authorization_code");
    outbound.set("code", code);
    outbound.set("code_verifier", verifier);
    outbound.set("redirect_uri", redirect);

    const provider = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: outbound,
    });
    if (!provider.ok) {
      return text("rejected", 502);
    }

    let payload;
    try {
      payload = await provider.json();
    } catch {
      return text("rejected", 502);
    }

    if (typeof payload.id_token !== "string" || payload.id_token.length < 20 || payload.id_token.length > 20000) {
      return text("rejected", 502);
    }

    return new Response(JSON.stringify({ id_token: payload.id_token }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    });
  };
}

function callbackFor(request) {
  const url = new URL(request.url);
  if (url.protocol !== "https:") {
    return null;
  }

  return `${url.origin}/callback`;
}

function isBounded(value, max) {
  return value.length > 0 && value.length <= max;
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
