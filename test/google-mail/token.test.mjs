import assert from "node:assert/strict";
import test from "node:test";
import { createStateNamespace } from "../helpers/dpop-state.mjs";
import { keyPair, signProof, thumbprint, verifierChallenge } from "../helpers/dpop.mjs";
import { issueTicket } from "../../functions/_shared/ticket.js";
import { unwrapRefreshToken, wrapRefreshToken } from "../../functions/_shared/token-state.js";
import { authorizeKeyRevocation, onRequestPost, revokeRegisteredKey, verifyDpop } from "../../functions/google-mail/token.js";

const authOrigin = "https://auth.example.test";
const hmac = "0123456789abcdef0123456789abcdef";
const rawKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
const envBase = {
  AUTH_TICKET_HMAC_KEY: hmac,
  GOOGLE_CLIENT_ID: "google-mail-client",
  GOOGLE_CLIENT_SECRET: "host-only-secret",
  REFRESH_TOKEN_KEYS: JSON.stringify({ k1: rawKey }),
  REFRESH_TOKEN_ACTIVE_KID: "k1",
};
const verifier = "verifier-01234567890123456789012345678901234567890";
const challenge = verifierChallenge(verifier);

async function brokerTicket() {
  return issueTicket({ AUTH_TICKET_HMAC_KEY: hmac }, {
    aud: authOrigin,
    returnUrl: "https://appliance.example.test/connectors",
    connector: "kautuka-google-mail",
    state: "s".repeat(43),
    challenge,
    nonce: "",
    microsoftAccountType: "",
  });
}

function codeForm(ticket) {
  return new URLSearchParams({
    grant_type: "authorization_code",
    scope: "https://www.googleapis.com/auth/gmail.modify",
    code: "provider-code",
    code_verifier: verifier,
    redirect_uri: `${authOrigin}/callback`,
    broker_ticket: ticket,
    return_origin: "https://appliance.example.test",
  });
}

test("Google code exchange validates broker ticket, PKCE, DPoP nonce, and wraps refresh token", async () => {
  const namespace = createStateNamespace();
  const env = { ...envBase, DPOP_STATE: namespace };
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const ticket = await brokerTicket();
  const body = codeForm(ticket);
  const target = `${authOrigin}/google-mail/token`;
  const firstProof = await signProof(pair, { htu: target });
  const challengeResponse = await onRequestPost({ env, request: mailRequest(target, body, firstProof) });
  assert.equal(challengeResponse.status, 400);
  assert.equal((await challengeResponse.json()).error, "use_dpop_nonce");
  const nonce = challengeResponse.headers.get("dpop-nonce");
  assert.ok(nonce);

  const previousFetch = globalThis.fetch;
  let outbound;
  let outboundHeaders;
  globalThis.fetch = async (url, init) => {
    assert.equal(String(url), "https://oauth2.googleapis.com/token");
    outbound = new URLSearchParams(init.body);
    outboundHeaders = init.headers;
    return json({ access_token: "google-access", refresh_token: "google-refresh-secret", expires_in: 3600, scope: "mail" });
  };
  try {
    const proof = await signProof(pair, { htu: target, nonce });
    const response = await onRequestPost({ env, request: mailRequest(target, body, proof) });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.access_token, "google-access");
    assert.match(result.refresh_token, /^krt1\.k1\./);
    assert.doesNotMatch(JSON.stringify(result), /google-refresh-secret|host-only-secret/);
    assert.equal(await unwrapRefreshToken(env, "google-mail", jkt, result.refresh_token), "google-refresh-secret");
    assert.equal(outbound.get("client_id"), "google-mail-client");
    assert.equal(outbound.get("client_secret"), "host-only-secret");
    assert.equal(outbound.get("code_verifier"), verifier);
    assert.equal(outbound.get("redirect_uri"), `${authOrigin}/callback`);
    assert.equal(outbound.has("broker_ticket"), false);
    assert.equal(outbound.has("return_origin"), false);
    assert.equal(outboundHeaders.dpop, undefined);
    const state = await namespace.get(namespace.idFromName(`google-mail:${jkt}`)).fetch("https://state.internal", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "get" }),
    });
    assert.deepEqual(await state.json(), { revoked: false });
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("an upstream failure stores no refresh credential or key allowlist entry", async () => {
  const namespace = createStateNamespace();
  const env = { ...envBase, DPOP_STATE: namespace };
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const ticket = await brokerTicket();
  const target = `${authOrigin}/google-mail/token`;
  const first = await onRequestPost({ env, request: mailRequest(target, codeForm(ticket), await signProof(pair, { htu: target })) });
  const nonce = first.headers.get("dpop-nonce");
  const previousFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return json({ error: "provider details must not escape", refresh_token: "provider-secret" }, 400); };
  try {
    const failed = await onRequestPost({ env, request: mailRequest(target, codeForm(ticket), await signProof(pair, { htu: target, nonce })) });
    assert.equal(failed.status, 400);
    assert.doesNotMatch(await failed.text(), /provider details|provider-secret/);
    assert.equal(calls, 1);
    const state = await namespace.get(namespace.idFromName(`google-mail:${jkt}`)).fetch("https://state.internal", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "get" }),
    });
    assert.deepEqual(await state.json(), { revoked: false });
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("two concurrent requests using one DPoP nonce and jti cause one upstream token request", async () => {
  const namespace = createStateNamespace();
  const env = { ...envBase, DPOP_STATE: namespace };
  const pair = await keyPair();
  const target = `${authOrigin}/google-mail/token`;
  const ticket = await brokerTicket();
  const body = codeForm(ticket);
  const first = await onRequestPost({ env, request: mailRequest(target, body, await signProof(pair, { htu: target })) });
  const nonce = first.headers.get("dpop-nonce");
  const proof = await signProof(pair, { htu: target, nonce, jti: "same-proof-jti-0123456789" });
  const previousFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; await new Promise((resolve) => setTimeout(resolve, 10)); return json({ access_token: "access", refresh_token: "refresh" }); };
  try {
    const responses = await Promise.all([
      onRequestPost({ env, request: mailRequest(target, body, proof) }),
      onRequestPost({ env, request: mailRequest(target, body, proof) }),
    ]);
    assert.equal(calls, 1);
    assert.equal(responses.filter((response) => response.status === 200).length, 1);
    assert.equal(responses.filter((response) => response.status === 400).length, 1);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("changing a replayed proof jti without changing the consumed nonce still fails", async () => {
  const namespace = createStateNamespace();
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const issued = await postState(namespace, "google-mail", jkt, "nonce");
  const nonce = issued.nonce;
  const first = await postState(namespace, "google-mail", jkt, "consume", { nonce, jti: "first-proof-jti-0123456789" });
  const changedJti = await postState(namespace, "google-mail", jkt, "consume", { nonce, jti: "changed-proof-jti-0123456789" });
  assert.equal(first.ok, true);
  assert.equal(changedJti.ok, false);
});

test("reusing a jti with a new nonce fails and provider plus thumbprint shard state separately", async () => {
  const namespace = createStateNamespace();
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const firstNonce = (await postState(namespace, "google-mail", jkt, "nonce")).nonce;
  assert.equal((await postState(namespace, "google-mail", jkt, "consume", { nonce: firstNonce, jti: "reused-proof-jti-0123456789" })).ok, true);
  const nextNonce = (await postState(namespace, "google-mail", jkt, "nonce")).nonce;
  assert.equal((await postState(namespace, "google-mail", jkt, "consume", { nonce: nextNonce, jti: "reused-proof-jti-0123456789" })).ok, false);
  assert.notEqual(namespace.idFromName(`google-mail:${jkt}`), namespace.idFromName(`microsoft-mail:${jkt}`));
});

test("Google refresh accepts only a provider and thumbprint bound envelope and blocks revoked keys", async () => {
  const namespace = createStateNamespace();
  const env = { ...envBase, DPOP_STATE: namespace };
  const pair = await keyPair();
  const otherPair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const otherJkt = await thumbprint(otherPair.publicKey);
  const wrapped = await (await import("../../functions/_shared/token-state.js")).wrapRefreshToken(env, "google-mail", jkt, "provider-refresh");
  const target = `${authOrigin}/google-mail/token`;
  const previousFetch = globalThis.fetch;
  let calls = 0;
  let providerRefresh;
  globalThis.fetch = async (_url, init) => {
    calls += 1;
    providerRefresh = new URLSearchParams(init.body).get("refresh_token");
    assert.equal(init.headers.dpop, undefined);
    return json({ access_token: "new-access", token_type: "Bearer" });
  };
  try {
    const nonce = (await postState(namespace, "google-mail", jkt, "nonce")).nonce;
    const success = await onRequestPost({
      env,
      request: mailRequest(target, new URLSearchParams({ grant_type: "refresh_token", scope: "https://www.googleapis.com/auth/gmail.modify", refresh_token: wrapped }), await signProof(pair, { htu: target, nonce })),
    });
    assert.equal(success.status, 200);
    const payload = await success.json();
    assert.equal(providerRefresh, "provider-refresh");
    assert.equal(await unwrapRefreshToken(env, "google-mail", jkt, payload.refresh_token), "provider-refresh");
    assert.doesNotMatch(JSON.stringify(payload), /provider-refresh/);

    const otherNonce = (await postState(namespace, "google-mail", otherJkt, "nonce")).nonce;
    const wrongKey = await onRequestPost({
      env,
      request: mailRequest(target, new URLSearchParams({ grant_type: "refresh_token", scope: "https://www.googleapis.com/auth/gmail.modify", refresh_token: wrapped }), await signProof(otherPair, { htu: target, nonce: otherNonce })),
    });
    assert.equal(wrongKey.status, 400);

    const rawNonce = (await postState(namespace, "google-mail", jkt, "nonce")).nonce;
    const raw = await onRequestPost({
      env,
      request: mailRequest(target, new URLSearchParams({ grant_type: "refresh_token", scope: "https://www.googleapis.com/auth/gmail.modify", refresh_token: "provider-refresh" }), await signProof(pair, { htu: target, nonce: rawNonce })),
    });
    assert.equal(raw.status, 400);
    assert.equal(calls, 1);

    await postState(namespace, "google-mail", jkt, "revoke");
    const revokedNonce = (await postState(namespace, "google-mail", jkt, "nonce")).nonce;
    const revoked = await onRequestPost({
      env,
      request: mailRequest(target, new URLSearchParams({ grant_type: "refresh_token", scope: "https://www.googleapis.com/auth/gmail.modify", refresh_token: wrapped }), await signProof(pair, { htu: target, nonce: revokedNonce })),
    });
    assert.equal(revoked.status, 403);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("DPoP rejects missing proofs, wrong URLs, and private JWK material", async () => {
  assert.equal((await verifyDpop(null, "refresh_token", null)).ok, false);
  const pair = await keyPair();
  const proof = await signProof(pair, { htu: `${authOrigin}/google-mail/token` });
  assert.equal((await verifyDpop(proof, "refresh_token", null, { htm: "POST", htu: `${authOrigin}/wrong` })).ok, false);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const header = Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: privateJwk })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ htm: "POST", htu: `${authOrigin}/google-mail/token`, iat: Math.floor(Date.now() / 1000), jti: "private-jwk-proof-123456" })).toString("base64url");
  assert.equal((await verifyDpop(`${header}.${payload}.${"A".repeat(86)}`, "refresh_token", null)).ok, false);
});
test("Google disconnect requires a decryptable envelope and a key-matching DPoP proof", async () => {
  const namespace = createStateNamespace();
  const env = { ...envBase, DPOP_STATE: namespace };
  const pair = await keyPair();
  const otherPair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const envelope = await wrapRefreshToken(env, "google-mail", jkt, "valid-refresh-secret");
  const wrongKeyProof = await signProof(otherPair, { htm: "DELETE", htu: `${authOrigin}/google-mail/keys/${jkt}` });
  const mismatch = await authorizeKeyRevocation(wrongKeyProof, null, jkt, `${authOrigin}/google-mail/keys/${jkt}`);
  assert.equal(mismatch.ok, false);

  const raw = await revokeRegisteredKey(env, deleteRequest(`${authOrigin}/google-mail/keys/${jkt}`, await signProof(pair, { htm: "DELETE", htu: `${authOrigin}/google-mail/keys/${jkt}` }), "raw-refresh"), jkt);
  assert.equal(raw.status, 403);
  const tampered = await revokeRegisteredKey(env, deleteRequest(`${authOrigin}/google-mail/keys/${jkt}`, await signProof(pair, { htm: "DELETE", htu: `${authOrigin}/google-mail/keys/${jkt}` }), `${envelope}x`), jkt);
  assert.equal(tampered.status, 403);

  const target = `${authOrigin}/google-mail/keys/${jkt}`;
  const challenge = await revokeRegisteredKey(env, deleteRequest(target, await signProof(pair, { htm: "DELETE", htu: target }), envelope), jkt);
  assert.equal(challenge.status, 400);
  const nonce = challenge.headers.get("dpop-nonce");
  const revoked = await revokeRegisteredKey(env, deleteRequest(target, await signProof(pair, { htm: "DELETE", htu: target, nonce }), envelope), jkt);
  assert.equal(revoked.status, 204);
  assert.deepEqual(await postState(namespace, "google-mail", jkt, "get"), { revoked: true });
});

function mailRequest(url, form, proof) {
  return new Request(url, { method: "POST", headers: { DPoP: proof }, body: form.toString() });
}

function deleteRequest(url, proof, refreshToken) {
  return new Request(url, { method: "DELETE", headers: { DPoP: proof, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ refresh_token: refreshToken }) });
}

async function postState(namespace, provider, jkt, action, extra = {}) {
  const stub = namespace.get(namespace.idFromName(`${provider}:${jkt}`));
  const response = await stub.fetch("https://state.internal", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...extra }),
  });
  return response.json();
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}
