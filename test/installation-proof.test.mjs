import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyInstallationProof } from "../functions/_shared/installation-proof.js";

const origin = "https://auth.kautuka.io";
const url = `${origin}/installation/flows`;
const encode = (value) => Buffer.from(value).toString("base64url");
const hash = async (value) => encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));

async function fixture(overrides = {}) {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const exported = await crypto.subtle.exportKey("jwk", key.publicKey);
  const jwk = { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y };
  const body = overrides.body ?? '{"purpose":"mail"}';
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "kautuka-installation+jwt", jwk, ...overrides.header };
  const claims = { aud: origin, htm: "POST", htu: url, iat: now, exp: now + 60,
    jti: encode(crypto.getRandomValues(new Uint8Array(32))), body_hash: await hash(body), ...overrides.claims };
  const unsigned = `${encode(JSON.stringify(header))}.${encode(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(unsigned));
  return { proof: `${unsigned}.${encode(signature)}`, body, jwk };
}

test("installation proof verifies possession and binds exact request body", async () => {
  const f = await fixture();
  const result = await verifyInstallationProof(f.proof, new Request(url, { method: "POST", body: f.body }), origin);
  assert.match(result.thumbprint, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(result.jwk, f.jwk);
  assert.equal(await verifyInstallationProof(f.proof, new Request(url, { method: "POST", body: "{}" }), origin), null);
});

test("installation proof rejects wrong method, endpoint, audience, age, and private key material", async () => {
  for (const f of [await fixture({ claims: { aud: "https://attacker.invalid" } }),
    await fixture({ claims: { exp: Math.floor(Date.now() / 1000) - 1 } }),
    await fixture({ header: { jwk: { kty: "EC", crv: "P-256", x: "A".repeat(43), y: "B".repeat(43), d: "secret" } } })]) {
    assert.equal(await verifyInstallationProof(f.proof, new Request(url, { method: "POST", body: f.body }), origin), null);
  }
  const f = await fixture();
  assert.equal(await verifyInstallationProof(f.proof, new Request(url, { method: "PUT", body: f.body }), origin), null);
  assert.equal(await verifyInstallationProof(f.proof, new Request(`${url}?x=1`, { method: "POST", body: f.body }), origin), null);
});

test("installation proof rejects oversized request bodies and altered signatures", async () => {
  const f = await fixture({ body: "a".repeat(32769) });
  assert.equal(await verifyInstallationProof(f.proof, new Request(url, { method: "POST", body: f.body }), origin), null);
  const good = await fixture();
  const parts = good.proof.split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  assert.equal(await verifyInstallationProof(`${parts[0]}.${parts[1]}.${signature.toString("base64url")}`,
    new Request(url, { method: "POST", body: good.body }), origin), null);
});

test("installation proof rejects non-string claims, wrong proof type, and excessive lifetimes", async () => {
  const now = Math.floor(Date.now() / 1000);
  const cases = [
    { claims: { jti: ["A".repeat(43)] } },
    { header: { typ: "dpop+jwt" } },
    { claims: { iat: now - 100, exp: now + 10 } },
    { claims: { iat: now + 31, exp: now + 60 } },
    { claims: { exp: now + 61 } },
  ];
  for (const options of cases) {
    const f = await fixture(options);
    assert.equal(await verifyInstallationProof(f.proof, new Request(url, { method: "POST", body: f.body }), origin), null);
  }
});
