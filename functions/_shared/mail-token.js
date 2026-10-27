import { hasDuplicateParameters } from "./forms.js";
import { isCanonicalOrigin } from "../../public/return-path.js";
import { readTicket } from "./ticket.js";
import { dpopState, isKeyringReady, unwrapRefreshToken, wrapRefreshToken } from "./token-state.js";

const maxBodyLength = 32_000;
const jktPattern = /^[A-Za-z0-9_-]{43}$/;

export function createMailTokenHandler(configuration) {
  return async function onRequestPost(context) {
    const env = context.env;
    if (!env[configuration.clientIdEnv] || !env[configuration.clientSecretEnv]
      || !env.DPOP_STATE || !isKeyringReady(env)) return text(`${configuration.providerName} mail sign-in is not configured.`, 503);

    const rawBody = await context.request.text();
    const proofHeader = context.request.headers.get("DPoP");
    if (!proofHeader || proofHeader.length > 4000 || rawBody.length > maxBodyLength) return text("rejected", 400);

    const form = new URLSearchParams(rawBody);
    const grantType = form.get("grant_type");
    if (hasDuplicateParameters(form) || form.has("client_id") || form.has("client_secret")
      || !["authorization_code", "refresh_token"].includes(grantType)) return text("rejected", 400);

    const redirectUri = callbackFor(context.request, configuration.providerId);
    if (!redirectUri) return text("rejected", 400);
    if (grantType === "authorization_code") {
      if (form.has("scope") && form.get("scope") !== configuration.scope) return text("rejected", 400);
      if (!hasOnlyParameters(form, ["grant_type", "code", "code_verifier", "redirect_uri", "broker_ticket", "return_origin", "scope"])) {
        return text("rejected", 400);
      }
      const ticket = await readTicket(env, form.get("broker_ticket"), new URL(context.request.url).origin);
      if (!ticket || ticket.connector !== configuration.ticketConnector
        || new URL(ticket.returnUrl).origin !== form.get("return_origin")
        || form.get("redirect_uri") !== redirectUri
        || !await matchesChallenge(form.get("code_verifier"), ticket.challenge)) return text("rejected", 400);
    } else if (form.has("scope") && form.get("scope") !== configuration.scope) {
      return text("rejected", 400);
    } else if (!hasOnlyParameters(form, ["grant_type", "refresh_token", "scope"])) {
      return text("rejected", 400);
    }

    const code = form.get("code");
    if (grantType === "authorization_code" && (!code || code.length > 2048)) return text("rejected", 400);
    const brokerTokenUrl = `${new URL(context.request.url).origin}/${configuration.providerId}/token`;
    const proof = await verifyDpop(proofHeader, grantType, code, { htm: "POST", htu: brokerTokenUrl });
    if (!proof.ok) return text("rejected", 400);

    const keyState = await dpopState(env, configuration.providerId, proof.jkt, { action: "get" });
    if (!keyState) return text("proof state unavailable", 503);
    if (keyState.revoked) return text("rejected", 403);
    const freshProofResponse = await requireFreshProof(env, configuration.providerId, proof);
    if (freshProofResponse) return freshProofResponse;

    let previousRefreshToken = "";
    if (grantType === "refresh_token") {
      const wrapped = form.get("refresh_token") ?? "";
      previousRefreshToken = await unwrapRefreshToken(env, configuration.providerId, proof.jkt, wrapped);
      if (!previousRefreshToken) return text("rejected", 400);
    }

    const providerForm = new URLSearchParams({
      client_id: env[configuration.clientIdEnv],
      client_secret: env[configuration.clientSecretEnv],
      grant_type: grantType,
      scope: configuration.scope,
    });
    if (grantType === "authorization_code") {
      providerForm.set("code", code);
      providerForm.set("code_verifier", form.get("code_verifier"));
      providerForm.set("redirect_uri", redirectUri);
    } else {
      providerForm.set("refresh_token", previousRefreshToken);
    }

    let providerResponse;
    try {
      providerResponse = await fetch(configuration.tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: providerForm,
      });
    } catch {
      return text(`${configuration.providerName} sign-in provider is unavailable.`, 502);
    }
    return formatTokenResponse(providerResponse, env, configuration.providerId, proof, grantType, previousRefreshToken);
  };
}

export function createMailKeyRevocationHandler(providerId) {
  return async function revokeRegisteredKey(env, request, jkt) {
    if (!env.DPOP_STATE || !isKeyringReady(env)) return text("Mail sign-in is not configured.", 503);
    const rawBody = await request.text();
    if (rawBody.length > maxBodyLength) return text("rejected", 400);
    const form = new URLSearchParams(rawBody);
    if (hasDuplicateParameters(form) || form.size !== 1 || !form.has("refresh_token")) return text("rejected", 400);

    const proof = await authorizeKeyRevocation(request.headers.get("DPoP"), null, jkt, request.url, providerId);
    if (!proof.ok) return text("rejected", 401);
    const keyState = await dpopState(env, providerId, proof.jkt, { action: "get" });
    const wrapped = form.get("refresh_token");
    if (!keyState || keyState.revoked || !await unwrapRefreshToken(env, providerId, proof.jkt, wrapped)) {
      return text("rejected", 403);
    }

    const freshProofResponse = await requireFreshProof(env, providerId, proof);
    if (freshProofResponse) return freshProofResponse;
    const revoked = await dpopState(env, providerId, proof.jkt, { action: "revoke" });
    if (!revoked?.ok) return text("rejected", 403);
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  };
}

async function formatTokenResponse(providerResponse, env, providerId, proof, grantType, previousRefreshToken) {
  const responseHeaders = { "cache-control": "no-store", "content-type": "application/json" };
  if (!providerResponse.ok) {
    return new Response(JSON.stringify({ error: "upstream_rejected" }), { status: providerResponse.status, headers: responseHeaders });
  }

  let providerPayload;
  try {
    providerPayload = await providerResponse.json();
  } catch {
    return text("rejected", 502);
  }
  if (typeof providerPayload.access_token !== "string" || !providerPayload.access_token
    || providerPayload.access_token.length > 20_000) return text("rejected", 502);

  const refreshToken = typeof providerPayload.refresh_token === "string" && providerPayload.refresh_token
    ? providerPayload.refresh_token
    : previousRefreshToken;
  if (!refreshToken && grantType === "authorization_code") return text("refresh token missing", 502);

  let wrappedRefreshToken;
  if (refreshToken) {
    try {
      wrappedRefreshToken = await wrapRefreshToken(env, providerId, proof.jkt, refreshToken);
    } catch {
      return text("token wrapping unavailable", 503);
    }
    const activeKey = await dpopState(env, providerId, proof.jkt, { action: "finalize" });
    if (!activeKey?.ok) return text("rejected", 403);
  }

  const result = {
    access_token: providerPayload.access_token,
    token_type: typeof providerPayload.token_type === "string" ? providerPayload.token_type : "Bearer",
  };
  if (typeof providerPayload.expires_in === "number" && Number.isFinite(providerPayload.expires_in)) {
    result.expires_in = providerPayload.expires_in;
  }
  if (typeof providerPayload.scope === "string") result.scope = providerPayload.scope;
  if (wrappedRefreshToken) result.refresh_token = wrappedRefreshToken;
  return Response.json(result, { headers: responseHeaders });
}

async function requireFreshProof(env, providerId, proof) {
  if (proof.nonce) {
    const consumed = await dpopState(env, providerId, proof.jkt, {
      action: "consume",
      nonce: proof.nonce,
      jti: proof.jti,
    });
    if (consumed?.ok) return null;
  }
  const issued = await dpopState(env, providerId, proof.jkt, { action: "nonce" });
  if (!issued?.nonce) return text("proof state unavailable", 503);
  return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
    status: 400,
    headers: { "content-type": "application/json", "cache-control": "no-store", "dpop-nonce": issued.nonce },
  });
}

export async function authorizeKeyRevocation(dpop, _authorization, jkt, requestUrl, expectedProvider) {
  if (!jktPattern.test(jkt ?? "")) return { ok: false };
  let url;
  try {
    url = new URL(requestUrl);
  } catch {
    return { ok: false };
  }
  const pathMatch = url.pathname.match(/^\/(google-mail|microsoft-mail)\/keys\/([A-Za-z0-9_-]{43})$/);
  if (url.protocol !== "https:" || !isCanonicalOrigin(url.origin) || url.search || url.hash
    || !pathMatch || pathMatch[2] !== jkt || expectedProvider && pathMatch[1] !== expectedProvider) return { ok: false };

  const proof = await verifyDpop(dpop, "revoke", null, {
    htm: "DELETE",
    htu: `${url.origin}${url.pathname}`,
  });
  return { ...proof, ok: proof.ok === true && proof.jkt === jkt };
}

export async function verifyDpop(dpop, grantType, _code, target = { htm: "POST", htu: "https://auth.kautuka.io/google-mail/token" }) {
  if (typeof dpop !== "string" || dpop.length > 4000
    || !["authorization_code", "refresh_token", "revoke"].includes(grantType)) return { ok: false };
  const parts = dpop.split(".");
  if (parts.length !== 3 || parts[2].length !== 86) return { ok: false };

  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  } catch {
    return { ok: false };
  }

  const jwk = header?.jwk;
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !jwk || jwk.d
    || jwk.kty !== "EC" || jwk.crv !== "P-256"
    || typeof jwk.x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
    || typeof jwk.y !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jwk.y)) return { ok: false };
  if (payload.htm !== target.htm || payload.htu !== target.htu) return { ok: false };

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number" || !Number.isSafeInteger(payload.iat) || Math.abs(now - payload.iat) > 300
    || typeof payload.jti !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(payload.jti)
    || payload.nonce !== undefined && (typeof payload.nonce !== "string" || payload.nonce.length > 200)) return { ok: false };

  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signatureValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      decodeBase64Url(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!signatureValid) return { ok: false };
    return { ok: true, jkt: await thumbprint(jwk), jti: payload.jti, nonce: typeof payload.nonce === "string" ? payload.nonce : "" };
  } catch {
    return { ok: false };
  }
}

async function matchesChallenge(verifier, challenge) {
  if (typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
    || typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return encodeBase64Url(new Uint8Array(digest)) === challenge;
}

function callbackFor(request, providerId) {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !isCanonicalOrigin(url.origin)
    || url.username || url.password || url.search || url.hash || url.pathname !== `/${providerId}/token`) return null;
  return `${url.origin}/callback`;
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return encodeBase64Url(new Uint8Array(digest));
}

function hasOnlyParameters(form, allowed) {
  const allowedNames = new Set(allowed);
  for (const [name] of form) {
    if (!allowedNames.has(name)) return false;
  }
  return true;
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url");
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}



