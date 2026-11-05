// Installation proofs authenticate a key holder, not an official build or an operator.
// Replay protection is enforced by the installation's durable state after validation.
const encoder = new TextEncoder();
const tokenPart = /^[A-Za-z0-9_-]+$/;
const identifier = /^[A-Za-z0-9_-]{43}$/;
const allowedHeaders = new Set(["alg", "typ", "jwk"]);
const allowedClaims = new Set(["aud", "htm", "htu", "iat", "exp", "jti", "body_hash"]);

export async function dpopReplayFingerprint(proof) {
  return base64url(await crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify([proof.jkt, proof.jti]))));
}

export async function verifyInstallationProof(proof, request, expectedOrigin, now = Date.now()) {
  try {
    if (typeof proof !== "string" || proof.length > 4096 || typeof expectedOrigin !== "string") return null;
    const parts = proof.split(".");
    if (parts.length !== 3 || parts.some((part) => !part || !tokenPart.test(part))) return null;
    const header = decodeObject(parts[0]);
    const claims = decodeObject(parts[1]);
    if (!hasOnly(header, allowedHeaders) || !hasOnly(claims, allowedClaims)
      || header.alg !== "ES256" || header.typ !== "kautuka-installation+jwt") return null;

    const jwk = header.jwk;
    if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)
      || Object.keys(jwk).sort().join(",") !== "crv,kty,x,y"
      || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string"
      || !identifier.test(jwk.x ?? "") || !identifier.test(jwk.y ?? "")) return null;

    const url = new URL(request.url);
    if (url.origin !== expectedOrigin || url.username || url.password || url.search || url.hash
      || url.protocol !== "https:" || claims.aud !== expectedOrigin
      || claims.htu !== url.href || claims.htm !== request.method.toUpperCase()) return null;
    const seconds = Math.floor(now / 1000);
    if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
      || claims.iat > seconds + 30 || claims.iat < seconds - 90
      || claims.exp <= seconds || claims.exp <= claims.iat || claims.exp > claims.iat + 60
      || typeof claims.jti !== "string" || typeof claims.body_hash !== "string"
      || !identifier.test(claims.jti) || !identifier.test(claims.body_hash)) return null;

    const body = await readBoundedBody(request.clone(), 32768);
    if (body === null || claims.body_hash !== base64url(await crypto.subtle.digest("SHA-256", body))) return null;
    const signature = decodeBytes(parts[2]);
    if (signature.length !== 64) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, encoder.encode(`${parts[0]}.${parts[1]}`))) return null;
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    const thumbprint = base64url(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
    return { jwk, thumbprint, jti: claims.jti, expiresAt: claims.exp * 1000 };
  } catch {
    return null;
  }
}

export async function readBoundedBody(request, limit) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        // A cloned request may tee the input stream; do not wait on the other branch.
        void reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function decodeObject(part) {
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBytes(part)));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid object");
  return value;
}

function hasOnly(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function decodeBytes(value) {
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64url(bytes) !== value) throw new Error("noncanonical base64url");
  return bytes;
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
