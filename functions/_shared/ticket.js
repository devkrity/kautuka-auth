import { isAllowedReturn, isCanonicalOrigin } from "../../public/return-path.js";

const connectors = new Set([
  "kautuka-google-mail",
  "kautuka-m365-mail",
  "kautuka-login-google",
  "kautuka-login-microsoft",
]);
const ticketLifetimeSeconds = 300;
const pkcePattern = /^[A-Za-z0-9_-]{43,128}$/;

export function validReturn(value, connector) {
  return isAllowedReturn(value, connector);
}

export async function issueTicket(env, claims) {
  if (!validSigningKey(env.AUTH_TICKET_HMAC_KEY) || !isValidClaims(claims)) {
    throw new Error("Invalid broker ticket configuration or claims");
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = { ...claims, iat: now, exp: now + ticketLifetimeSeconds };
  const body = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await importHmacKey(env.AUTH_TICKET_HMAC_KEY, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return `${body}.${encodeBase64Url(new Uint8Array(signature))}`;
}

export async function readTicket(env, ticket, audience) {
  if (!validSigningKey(env.AUTH_TICKET_HMAC_KEY) || typeof ticket !== "string" || ticket.length > 5000) return null;

  const [body, signature, ...extra] = ticket.split(".");
  if (!body || !signature || extra.length !== 0) return null;

  try {
    const key = await importHmacKey(env.AUTH_TICKET_HMAC_KEY, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, decodeBase64Url(signature), new TextEncoder().encode(body))) return null;

    const claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(body)));
    const now = Math.floor(Date.now() / 1000);
    if (!isValidClaims(claims)
      || !Number.isSafeInteger(claims.iat)
      || !Number.isSafeInteger(claims.exp)
      || claims.iat > now + 15
      || claims.exp <= now
      || claims.exp <= claims.iat
      || claims.exp - claims.iat > ticketLifetimeSeconds
      || (audience !== undefined && claims.aud !== audience)) return null;
    return claims;
  } catch {
    return null;
  }
}

function isValidClaims(claims) {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) return false;
  if (typeof claims.aud !== "string" || !isOrigin(claims.aud)) return false;
  if (typeof claims.returnUrl !== "string" || !validReturn(claims.returnUrl, claims.connector)) return false;
  if (!pkcePattern.test(claims.state ?? "") || !pkcePattern.test(claims.challenge ?? "")) return false;
  if (typeof claims.nonce !== "string" || claims.nonce.length > 128) return false;
  if (claims.connector.startsWith("kautuka-login-") && !pkcePattern.test(claims.nonce)) return false;
  if (claims.microsoftAccountType !== "" && !["organizations", "consumers"].includes(claims.microsoftAccountType)) return false;
  if (claims.microsoftAccountType && claims.connector !== "kautuka-login-microsoft") return false;
  return true;
}

function isOrigin(value) {
  return isCanonicalOrigin(value);
}

function validSigningKey(value) {
  return typeof value === "string" && value.length >= 32 && value.length <= 512;
}

async function importHmacKey(secret, usages) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usages);
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded + "=".repeat((4 - padded.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}







