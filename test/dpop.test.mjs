import assert from "node:assert/strict";
import test from "node:test";
import { verifyDpop } from "../functions/_shared/dpop.js";

const encode = value => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
const target = { htm: "POST", htu: "https://auth.example.test/installation/mail-status" };

test("current mail DPoP verifier checks signature, key, method, target and age", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = await crypto.subtle.exportKey("jwk", key.publicKey);
  const make = async (headerChanges = {}, claimChanges = {}) => {
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: publicKey, ...headerChanges };
    const claims = { ...target, iat: Math.floor(Date.now() / 1000), jti: "a".repeat(32), ...claimChanges };
    const input = `${encode(header)}.${encode(claims)}`;
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(input));
    return `${input}.${Buffer.from(signature).toString("base64url")}`;
  };
  assert.equal((await verifyDpop(await make(), "refresh_token", null, target)).ok, true);
  for (const proof of [await make({ alg: "none" }), await make({ jwk: { ...publicKey, d: "private" } }),
    await make({}, { htm: "GET" }), await make({}, { htu: "https://evil.example/" }),
    await make({}, { iat: Math.floor(Date.now() / 1000) - 400 })]) {
    assert.equal((await verifyDpop(proof, "refresh_token", null, target)).ok, false);
  }
  assert.equal((await verifyDpop("bad.proof.value", "refresh_token", null, target)).ok, false);
});
