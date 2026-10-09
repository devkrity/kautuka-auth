import { authorizeKeyRevocation, verifyDpop } from "../google-mail/token.js";

const tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const scope = "offline_access Mail.ReadWrite Mail.Send User.Read";

export async function onRequestPost(context) {
  const clientId = context.env.MICROSOFT_CLIENT_ID;
  const clientSecret = context.env.MICROSOFT_CLIENT_SECRET;
  const keys = context.env.MICROSOFT_MAIL_KEYS;
  if (!clientId || !clientSecret || !keys || typeof keys.get !== "function" || typeof keys.put !== "function") {
    return text("Microsoft mail sign-in is not configured.", 503);
  }

  const redirectUri = callbackFor(context.request);
  const body = await context.request.text();
  const dpop = context.request.headers.get("DPoP");
  if (!redirectUri || !dpop || dpop.length > 4000 || body.length > 8000) {
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

  const proofUrl = `${new URL(context.request.url).origin}/microsoft-mail/token`;
  const proof = await verifyDpop(dpop, grant, form.get("code"), { htm: "POST", htu: proofUrl });
  if (!proof.ok) {
    return text("rejected", 400);
  }

  const fresh = await requireFreshProof(keys, proof);
  if (fresh) {
    return fresh;
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

export async function revokeRegisteredKey(env, request, jkt) {
  const keys = env.MICROSOFT_MAIL_KEYS;
  if (!keys || typeof keys.delete !== "function") {
    return text("Microsoft mail sign-in is not configured.", 503);
  }

  const decision = await authorizeKeyRevocation(
    request.headers.get("DPoP"),
    request.headers.get("authorization"),
    jkt,
    request.url,
  );
  if (!decision.ok) {
    return text("rejected", 401);
  }

  await keys.delete(jkt);
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function requireFreshProof(keys, proof) {
  const nonce = proof.nonce;
  if (typeof nonce !== "string" || nonce.length < 16 || !(await keys.get(`nonce:${nonce}`))) {
    const issued = randomNonce();
    await keys.put(`nonce:${issued}`, "1", { expirationTtl: 300 });
    return nonceRequired(issued);
  }

  if (await keys.get(`jti:${proof.jti}`)) {
    return text("rejected", 400);
  }

  await keys.put(`jti:${proof.jti}`, "1", { expirationTtl: 300 });
  return null;
}

function randomNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function nonceRequired(nonce) {
  return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
    status: 400,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "dpop-nonce": nonce,
    },
  });
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
