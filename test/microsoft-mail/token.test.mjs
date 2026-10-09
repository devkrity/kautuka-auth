import assert from "node:assert/strict";
import test from "node:test";

import { onRequestPost, revokeRegisteredKey } from "../../functions/microsoft-mail/token.js";

const clientId = "11111111-1111-1111-1111-111111111111";
const clientSecret = "host-only-secret";

test("a token request that already carries a client id is rejected", async () => {
  const response = await onRequestPost({
    env: { MICROSOFT_CLIENT_ID: clientId, MICROSOFT_CLIENT_SECRET: clientSecret, MICROSOFT_MAIL_KEYS: memoryKeys() },
    request: new Request("https://auth.example.test/microsoft-mail/token", {
      method: "POST",
      headers: { DPoP: "a.b.c" },
      body: "grant_type=authorization_code&client_id=caller&code=c&code_verifier=v&redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback",
    }),
  });
  assert.equal(response.status, 400);
});

test("the auth host adds the Microsoft client id and keeps the code verifier", async () => {
  const previous = globalThis.fetch;
  let forwarded = "";
  let forwardedHeaders = null;
  globalThis.fetch = async (_url, init) => {
    forwarded = init.body.toString();
    forwardedHeaders = init.headers;
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const proof = await signProof(key, "auth-code", {
      htu: "https://auth.example.test/microsoft-mail/token",
    });
    const stored = new Map();
    const response = await onRequestPost({
      env: { MICROSOFT_CLIENT_ID: clientId, MICROSOFT_CLIENT_SECRET: clientSecret, MICROSOFT_MAIL_KEYS: memoryKeys(stored) },
      request: new Request("https://auth.example.test/microsoft-mail/token", {
        method: "POST",
        headers: { DPoP: proof },
        body: "grant_type=authorization_code&code=auth-code&code_verifier=verifier-secret&redirect_uri=https://auth.example.test/callback",
      }),
    });
    assert.equal(response.status, 200);
    assert.match(forwarded, /client_id=11111111-1111-1111-1111-111111111111/);
    assert.match(forwarded, /code_verifier=verifier-secret/);
    assert.match(forwarded, /client_secret=host-only-secret/);
    assert.doesNotMatch(forwarded, /client_secret=caller/);
    assert.equal(forwardedHeaders.dpop, undefined);
    assert.equal(stored.size, 1);
  } finally {
    globalThis.fetch = previous;
  }
});

test("a refresh without a registered key is rejected", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const proof = await signProof(key, null, {
    htu: "https://auth.example.test/microsoft-mail/token",
    jti: "0123456789abcdef",
  });
  const response = await onRequestPost({
    env: { MICROSOFT_CLIENT_ID: clientId, MICROSOFT_CLIENT_SECRET: clientSecret, MICROSOFT_MAIL_KEYS: memoryKeys() },
    request: new Request("https://auth.example.test/microsoft-mail/token", {
      method: "POST",
      headers: { DPoP: proof },
      body: "grant_type=refresh_token&refresh_token=token",
    }),
  });
  assert.equal(response.status, 403);
});

test("disconnect removes the registered Microsoft key", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const jkt = await thumbprint(await crypto.subtle.exportKey("jwk", key.publicKey));
  const proof = await signProof(key, null, {
    htm: "DELETE",
    htu: `https://auth.kautuka.io/microsoft-mail/keys/${jkt}`,
    jti: "0123456789abcdef",
  });
  const stored = new Map([[jkt, "1"]]);
  const response = await revokeRegisteredKey(
    { MICROSOFT_MAIL_KEYS: memoryKeys(stored) },
    new Request("https://auth.kautuka.io/microsoft-mail/keys/" + jkt, { method: "DELETE", headers: { DPoP: proof } }),
    jkt,
  );
  assert.equal(response.status, 204);
  assert.equal(stored.has(jkt), false);
});

function memoryKeys(stored = new Map()) {
  return {
    get: (name) => stored.get(name) ?? null,
    put: (name, value) => stored.set(name, value),
    delete: (name) => stored.delete(name),
  };
}

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
    htu: target.htu ?? "https://auth.example.test/microsoft-mail/token",
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
