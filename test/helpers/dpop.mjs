import { createHash, randomBytes } from "node:crypto";

export async function keyPair() {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

export async function thumbprint(publicKey) {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  const data = new TextEncoder().encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

export async function signProof(pair, { htm = "POST", htu, jti = randomBytes(24).toString("base64url"), nonce } = {}) {
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const header = base64url(new TextEncoder().encode(JSON.stringify({
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: "EC", crv: "P-256", x: publicJwk.x, y: publicJwk.y },
  })));
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
    jti,
    ...(nonce ? { nonce } : {}),
  })));
  const signed = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${header}.${payload}`),
  ));
  return `${header}.${payload}.${base64url(signed)}`;
}

export function verifierChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
