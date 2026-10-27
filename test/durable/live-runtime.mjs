import assert from "node:assert/strict";
import { keyPair, signProof, thumbprint } from "../helpers/dpop.mjs";
import { wrapRefreshToken } from "../../functions/_shared/token-state.js";

const baseUrl = process.env.AUTH_TEST_BASE_URL;
if (!baseUrl?.startsWith("https://127.0.0.1:")) throw new Error("Set AUTH_TEST_BASE_URL to the local Wrangler Worker HTTPS URL.");

const target = `${baseUrl}/google-mail/token`;
const startPage = await fetch(`${baseUrl}/start/`);
assert.equal(startPage.status, 200);
assert.equal(startPage.headers.get("x-frame-options"), "DENY");
assert.match(startPage.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
assert.equal(startPage.headers.get("x-content-type-options"), "nosniff");

const env = {
  REFRESH_TOKEN_KEYS: JSON.stringify({ k1: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }),
  REFRESH_TOKEN_ACTIVE_KID: "k1",
};
const pair = await keyPair();
const jkt = await thumbprint(pair.publicKey);
const body = new URLSearchParams({
  grant_type: "refresh_token",
  scope: "https://www.googleapis.com/auth/gmail.modify",
  refresh_token: "raw-refresh-token-is-rejected-before-upstream",
});

const initialProof = await signProof(pair, { htu: target });
const challenge = await fetch(target, { method: "POST", headers: { DPoP: initialProof }, body });
assert.equal(challenge.status, 400);
const nonce = challenge.headers.get("dpop-nonce");
assert.ok(nonce);

const repeatedProof = await signProof(pair, {
  htu: target,
  nonce,
  jti: "live-runtime-replay-jti-0000001",
});
const concurrentResponses = await Promise.all([
  fetch(target, { method: "POST", headers: { DPoP: repeatedProof }, body }),
  fetch(target, { method: "POST", headers: { DPoP: repeatedProof }, body }),
]);
const concurrentBodies = await Promise.all(concurrentResponses.map((response) => response.text()));
assert.deepEqual(concurrentBodies.sort(), ["rejected", JSON.stringify({ error: "use_dpop_nonce" })].sort());

const wrapped = await wrapRefreshToken(env, "google-mail", jkt, "local-provider-refresh");
const revokeUrl = `${baseUrl}/google-mail/keys/${jkt}`;
const revokeBody = new URLSearchParams({ refresh_token: wrapped });
const revokeChallenge = await fetch(revokeUrl, {
  method: "DELETE",
  headers: { DPoP: await signProof(pair, { htm: "DELETE", htu: revokeUrl }) },
  body: revokeBody,
});
assert.equal(revokeChallenge.status, 400);
const revokeNonce = revokeChallenge.headers.get("dpop-nonce");
assert.ok(revokeNonce);
const revoked = await fetch(revokeUrl, {
  method: "DELETE",
  headers: { DPoP: await signProof(pair, { htm: "DELETE", htu: revokeUrl, nonce: revokeNonce }) },
  body: revokeBody,
});
assert.equal(revoked.status, 204);

const afterRevocation = await fetch(target, {
  method: "POST",
  headers: { DPoP: await signProof(pair, { htu: target }) },
  body: new URLSearchParams({
    grant_type: "refresh_token",
    scope: "https://www.googleapis.com/auth/gmail.modify",
    refresh_token: wrapped,
  }),
});
assert.equal(afterRevocation.status, 403);
console.log("Local Durable Object nonce replay and revocation checks passed.");
