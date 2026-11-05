import { readBoundedBody } from "./installation-proof.js";

// This key defines account identity, so silently replacing it resets quota
// identity. Operators must retain it with durable state until a reviewed
// migration or coordinated reset is available.
export function isMailIdentityConfigured(env) {
  try {
    const value = env.MAIL_ACCOUNT_PSEUDONYM_KEY;
    return typeof value === "string" && /^[A-Za-z0-9+/]{43}=$/.test(value)
      && atob(value).length === 32 && btoa(atob(value)) === value;
  } catch { return false; }
}

// Resolve the account using the same provider access token that grants mail
// access. Never trust account identifiers supplied by an installation.
export async function resolveMailAccount(env, provider, installationId, accessToken) {
  const endpoint = provider === "google" ? "https://openidconnect.googleapis.com/v1/userinfo"
    : provider === "microsoft" ? "https://graph.microsoft.com/v1.0/me?$select=id" : null;
  if (!endpoint || !/^[A-Za-z0-9_-]{43}$/.test(installationId ?? "")
    || typeof accessToken !== "string" || accessToken.length < 1 || accessToken.length > 20000
    || !isMailIdentityConfigured(env)) return null;
  try {
    const keyBytes = Uint8Array.from(atob(env.MAIL_ACCOUNT_PSEUDONYM_KEY), (character) => character.charCodeAt(0));
    if (keyBytes.length !== 32) return null;
    const response = await fetch(endpoint, { method: "GET", headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      redirect: "manual", signal: AbortSignal.timeout(15000) });
    if (!response.ok) return null;
    const bytes = await readBoundedBody(response, 16384);
    if (!bytes) return null;
    const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    const subject = provider === "google" ? payload?.sub : payload?.id;
    if (typeof subject !== "string" || subject.length < 1 || subject.length > 255 || /[\u0000-\u001f\u007f]/.test(subject)) return null;
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const message = new TextEncoder().encode(JSON.stringify(["mail-account-v1", installationId, provider, subject]));
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
    return btoa(String.fromCharCode(...digest)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  } catch { return null; }
}
