const tokenEndpoint = "https://oauth2.googleapis.com/token";
const scope = "https://www.googleapis.com/auth/gmail.modify";

export async function onRequestPost(context) {
  const clientId = context.env.GOOGLE_CLIENT_ID;
  const clientSecret = context.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return text("Google mail sign-in is not configured.", 503);
  }

  const keys = context.env.GOOGLE_MAIL_KEYS;
  if (!keys || typeof keys.get !== "function" || typeof keys.put !== "function") {
    return text("Google mail sign-in is not configured.", 503);
  }

  const dpop = context.request.headers.get("DPoP");
  const body = await context.request.text();
  if (!dpop || dpop.length > 4000 || body.length > 8000) {
    return text("rejected", 400);
  }

  const redirectUri = callbackFor(context.request);
  const form = new URLSearchParams(body);
  if (!redirectUri || form.has("client_secret") || form.has("client_id")) {
    return text("rejected", 400);
  }

  const grant = form.get("grant_type");
  const proof = await verifyDpop(dpop, grant, form.get("code"));
  if (!proof.ok) {
    return text("rejected", 400);
  }

  if (grant === "authorization_code" && form.get("redirect_uri") !== redirectUri) {
    return text("rejected", 400);
  }

  if (grant === "authorization_code") {
    await keys.put(proof.jkt, "1");
  } else {
    const allowed = await keys.get(proof.jkt);
    if (!allowed) {
      return text("rejected", 403);
    }
  }

  const outbound = new URLSearchParams();
  outbound.set("client_id", clientId);
  outbound.set("client_secret", clientSecret);
  outbound.set("grant_type", grant);
  outbound.set("scope", scope);
  if (grant === "authorization_code") {
    outbound.set("code", form.get("code") ?? "");
    outbound.set("code_verifier", form.get("code_verifier") ?? "");
    outbound.set("redirect_uri", redirectUri);
  } else {
    outbound.set("refresh_token", form.get("refresh_token") ?? "");
  }

  const google = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
      dpop,
    },
    body: outbound,
  });
  const headers = new Headers();
  headers.set("content-type", "application/json");
  headers.set("cache-control", "no-store");
  const nonce = google.headers.get("dpop-nonce");
  if (nonce && nonce.length <= 200) {
    headers.set("dpop-nonce", nonce);
  }

  return new Response(google.body, { status: google.status, headers });
}

function callbackFor(request) {
  const url = new URL(request.url);
  if (url.protocol !== "https:") {
    return null;
  }

  return `${url.origin}/callback`;
}

export async function authorizeKeyRevocation(dpop, authorization, jkt, revokeToken, requestUrl) {
  if (typeof jkt !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jkt)) {
    return { ok: false };
  }

  let keyUrl;
  try {
    keyUrl = new URL(requestUrl ?? `https://auth.kautuka.io/google-mail/keys/${jkt}`);
  } catch {
    return { ok: false };
  }

  if (keyUrl.protocol !== "https:"
    || keyUrl.pathname !== `/google-mail/keys/${jkt}`
    || keyUrl.search
    || keyUrl.hash) {
    return { ok: false };
  }

  if (typeof revokeToken === "string" && revokeToken.length > 0 && authorization === `Bearer ${revokeToken}`) {
    return { ok: true };
  }

  const proof = await verifyDpop(dpop ?? "", "revoke", null, {
    htm: "DELETE",
    htu: `${keyUrl.origin}/google-mail/keys/${jkt}`,
  });
  return { ok: proof.ok === true && proof.jkt === jkt };
}

export async function revokeRegisteredKey(env, request, jkt) {
  const keys = env.GOOGLE_MAIL_KEYS;
  if (!keys || typeof keys.delete !== "function") {
    return text("Google mail sign-in is not configured.", 503);
  }

  const decision = await authorizeKeyRevocation(
    request.headers.get("DPoP"),
    request.headers.get("authorization"),
    jkt,
    env.REVOKE_TOKEN,
    request.url,
  );
  if (!decision.ok) {
    return text("rejected", 401);
  }

  await keys.delete(jkt);
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

export async function verifyDpop(dpop, grant, code, target = { htm: "POST", htu: tokenEndpoint }) {
  const parts = dpop.split(".");
  if (parts.length !== 3 || (grant !== "authorization_code" && grant !== "refresh_token" && grant !== "revoke")) {
    return { ok: false };
  }

  let header;
  let payload;
  try {
    header = JSON.parse(decode(parts[0]));
    payload = JSON.parse(decode(parts[1]));
  } catch {
    return { ok: false };
  }

  const jwk = header.jwk;
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !jwk || jwk.d) {
    return { ok: false };
  }

  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    return { ok: false };
  }

  if (payload.htm !== target.htm || payload.htu !== target.htu) {
    return { ok: false };
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number" || Math.abs(now - payload.iat) > 300) {
    return { ok: false };
  }

  if (grant === "authorization_code") {
    if (!code) {
      return { ok: false };
    }

    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
    if (payload.jti !== base64Url(new Uint8Array(digest))) {
      return { ok: false };
    }
  } else if (grant === "revoke" || grant === "refresh_token") {
    if (typeof payload.jti !== "string" || payload.jti.length < 16) {
      return { ok: false };
    }
  } else {
    return { ok: false };
  }

  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      base64UrlDecode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!valid) {
      return { ok: false };
    }

    return { ok: true, jkt: await thumbprint(jwk) };
  } catch {
    return { ok: false };
  }
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64Url(new Uint8Array(digest));
}

function decode(value) {
  return new TextDecoder().decode(base64UrlDecode(value));
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "cache-control": "no-store" },
  });
}
