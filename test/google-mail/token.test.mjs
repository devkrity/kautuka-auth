import assert from "node:assert/strict";
import test from "node:test";

import { authorizeKeyRevocation, onRequestPost, revokeRegisteredKey, verifyDpop } from "../../functions/google-mail/token.js";

test("a DPoP proof for the Google token endpoint is accepted", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const code = "auth-code";
  const proof = await signProof(key, code);
  const result = await verifyDpop(proof, "authorization_code", code);
  assert.equal(result.ok, true);
  assert.equal(typeof result.jkt, "string");
});

test("a refresh is rejected when the key list is not configured", async () => {
  const response = await onRequestPost({
    env: { GOOGLE_CLIENT_ID: "client", GOOGLE_CLIENT_SECRET: "secret" },
    request: new Request("https://auth.kautuka.io/google-mail/token", {
      method: "POST",
      headers: { DPoP: "a.b.c" },
      body: "grant_type=refresh_token&refresh_token=token",
    }),
  });
  assert.equal(response.status, 503);
});

test("disconnect removes the registered key when the DPoP proof matches it", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const jkt = await thumbprint(await crypto.subtle.exportKey("jwk", key.publicKey));
  const proof = await signProof(key, null, {
    htm: "DELETE",
    htu: `https://auth.kautuka.io/google-mail/keys/${jkt}`,
    jti: "0123456789abcdef",
  });
  const stored = new Map([[jkt, "1"]]);
  const response = await revokeRegisteredKey(
    { GOOGLE_MAIL_KEYS: { delete: (name) => stored.delete(name) } },
    new Request("https://auth.kautuka.io/google-mail/keys/" + jkt, { method: "DELETE", headers: { DPoP: proof } }),
    jkt,
  );
  assert.equal(response.status, 204);
  assert.equal(stored.has(jkt), false);
});

test("disconnect is rejected when the proof is for a different key", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const jkt = await thumbprint(await crypto.subtle.exportKey("jwk", other.publicKey));
  const proof = await signProof(key, null, {
    htm: "DELETE",
    htu: `https://auth.kautuka.io/google-mail/keys/${jkt}`,
    jti: "0123456789abcdef",
  });
  const decision = await authorizeKeyRevocation(proof, null, jkt, null);
  assert.equal(decision.ok, false);
});

test("a proof that carries the private key is rejected", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const exported = await crypto.subtle.exportKey("jwk", key.privateKey);
  const header = base64Url(JSON.stringify({
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: "EC", crv: "P-256", x: exported.x, y: exported.y, d: exported.d },
  }));
  const payload = base64Url(JSON.stringify({
    htm: "POST",
    htu: "https://oauth2.googleapis.com/token",
    iat: Math.floor(Date.now() / 1000),
    jti: "0123456789abcdef",
  }));
  const result = await verifyDpop(`${header}.${payload}.sig`, "refresh_token", null);
  assert.equal(result.ok, false);
});

async function signProof(key, code, target = {}) {
  const exported = await crypto.subtle.exportKey("jwk", key.publicKey);
  const header = base64Url(JSON.stringify({
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: "EC", crv: "P-256", x: exported.x, y: exported.y },
  }));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code ?? ""));
  const payload = base64Url(JSON.stringify({
    htm: target.htm ?? "POST",
    htu: target.htu ?? "https://oauth2.googleapis.com/token",
    iat: Math.floor(Date.now() / 1000),
    jti: target.jti ?? base64UrlBytes(new Uint8Array(digest)),
  }));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${base64UrlBytes(new Uint8Array(signature))}`;
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64UrlBytes(new Uint8Array(digest));
}

function base64Url(text) {
  return base64UrlBytes(new TextEncoder().encode(text));
}

function base64UrlBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
