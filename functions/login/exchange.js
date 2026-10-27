import { hasDuplicateParameters } from "../_shared/forms.js";
import { isCanonicalOrigin } from "../../public/return-path.js";
import { readTicket } from "../_shared/ticket.js";

const maxBodyLength = 8000;

export function createLoginExchange({ clientIdEnv, clientSecretEnv, tokenEndpoint, connector }) {
  return async function onRequestPost(context) {
    const clientId = context.env[clientIdEnv];
    const clientSecret = context.env[clientSecretEnv];
    if (!clientId || !clientSecret) return text("Sign-in is not configured.", 503);

    const rawBody = await context.request.text();
    if (rawBody.length > maxBodyLength) return text("rejected", 400);
    const form = new URLSearchParams(rawBody);
    if (hasDuplicateParameters(form) || form.has("client_secret") || form.has("client_id")) {
      return text("rejected", 400);
    }

    const redirectUri = canonicalCallback(context.request);
    const ticket = await readTicket(context.env, form.get("broker_ticket"), new URL(context.request.url).origin);
    const returnOrigin = form.get("return_origin");
    if (!ticket
      || ticket.connector !== connector
      || new URL(ticket.returnUrl).origin !== returnOrigin
      || !redirectUri
      || form.get("grant_type") !== "authorization_code"
      || form.get("redirect_uri") !== redirectUri) return text("rejected", 400);

    const code = form.get("code") ?? "";
    const verifier = form.get("code_verifier") ?? "";
    if (!isBounded(code, 2048) || !isBounded(verifier, 128)
      || !await matchesChallenge(verifier, ticket.challenge)) return text("rejected", 400);

    const outbound = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
    });
    let providerResponse;
    try {
      providerResponse = await fetch(tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: outbound,
      });
    } catch {
      return text("Sign-in provider is unavailable.", 502);
    }
    if (!providerResponse.ok) return text("rejected", 502);

    let payload;
    try {
      payload = await providerResponse.json();
    } catch {
      return text("rejected", 502);
    }
    if (typeof payload.id_token !== "string" || payload.id_token.length < 20 || payload.id_token.length > 20000) {
      return text("rejected", 502);
    }
    return Response.json({ id_token: payload.id_token }, { headers: { "cache-control": "no-store" } });
  };
}

export function canonicalCallback(request) {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !isCanonicalOrigin(url.origin)
    || url.username || url.password || url.search || url.hash
    || !["/login/google/token", "/login/microsoft/token"].includes(url.pathname)) return null;
  return `${url.origin}/callback`;
}

export async function matchesChallenge(verifier, challenge) {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
    || !/^[A-Za-z0-9_-]{43}$/.test(challenge ?? "")) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest)) === challenge;
}

function isBounded(value, maxLength) {
  return value.length > 0 && value.length <= maxLength;
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
