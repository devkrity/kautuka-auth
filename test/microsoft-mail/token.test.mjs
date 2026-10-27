import assert from "node:assert/strict";
import test from "node:test";
import { createStateNamespace, stateRequest } from "../helpers/dpop-state.mjs";
import { keyPair, signProof, thumbprint, verifierChallenge } from "../helpers/dpop.mjs";
import { issueTicket } from "../../functions/_shared/ticket.js";
import { unwrapRefreshToken, wrapRefreshToken } from "../../functions/_shared/token-state.js";
import { onRequestPost, revokeRegisteredKey } from "../../functions/microsoft-mail/token.js";

const authOrigin = "https://auth.example.test";
const secret = "0123456789abcdef0123456789abcdef";
const key = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
const envTemplate = {
  AUTH_TICKET_HMAC_KEY: secret,
  MICROSOFT_CLIENT_ID: "microsoft-client",
  MICROSOFT_CLIENT_SECRET: "microsoft-host-secret",
  REFRESH_TOKEN_KEYS: JSON.stringify({ k1: key }),
  REFRESH_TOKEN_ACTIVE_KID: "k1",
};
const verifier = "microsoft-verifier-0123456789012345678901234567";
const challenge = verifierChallenge(verifier);

async function createTicket() {
  return issueTicket({ AUTH_TICKET_HMAC_KEY: secret }, {
    aud: authOrigin,
    returnUrl: "https://appliance.example.test/connectors",
    connector: "kautuka-m365-mail",
    state: "S".repeat(43),
    challenge,
    nonce: "",
    microsoftAccountType: "",
  });
}

test("Microsoft mail exchanges with its broker DPoP URL and returns an encrypted refresh envelope", async () => {
  const namespace = createStateNamespace();
  const env = { ...envTemplate, DPOP_STATE: namespace };
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const target = `${authOrigin}/microsoft-mail/token`;
  const ticket = await createTicket();
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    scope: "offline_access Mail.ReadWrite Mail.Send User.Read",
    code: "microsoft-code",
    code_verifier: verifier,
    redirect_uri: `${authOrigin}/callback`,
    broker_ticket: ticket,
    return_origin: "https://appliance.example.test",
  });
  const first = await onRequestPost({ env, request: request(target, form, await signProof(pair, { htu: target })) });
  assert.equal(first.status, 400);
  const nonce = first.headers.get("dpop-nonce");
  assert.ok(nonce);

  const previous = globalThis.fetch;
  let endpoint;
  let outbound;
  let outboundHeaders;
  globalThis.fetch = async (url, init) => {
    endpoint = String(url);
    outbound = new URLSearchParams(init.body);
    outboundHeaders = init.headers;
    return json({ access_token: "ms-access", refresh_token: "ms-refresh-secret", expires_in: 3600, scope: "mail" });
  };
  try {
    const proof = await signProof(pair, { htu: target, nonce });
    const response = await onRequestPost({ env, request: request(target, form, proof) });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(endpoint, "https://login.microsoftonline.com/common/oauth2/v2.0/token");
    assert.equal(payload.access_token, "ms-access");
    assert.match(payload.refresh_token, /^krt1\.k1\./);
    assert.equal(await unwrapRefreshToken(env, "microsoft-mail", jkt, payload.refresh_token), "ms-refresh-secret");
    assert.equal(outbound.get("client_id"), "microsoft-client");
    assert.equal(outbound.get("client_secret"), "microsoft-host-secret");
    assert.equal(outbound.get("code_verifier"), verifier);
    assert.equal(outbound.has("broker_ticket"), false);
    assert.equal(outbound.has("return_origin"), false);
    assert.equal(outboundHeaders.dpop, undefined);
  } finally {
    globalThis.fetch = previous;
  }
});

test("Microsoft refresh unwraps only matching-key envelopes and rejects raw, other-key, and revoked tokens", async () => {
  const namespace = createStateNamespace();
  const env = { ...envTemplate, DPOP_STATE: namespace };
  const pair = await keyPair();
  const otherPair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const otherJkt = await thumbprint(otherPair.publicKey);
  const envelope = await wrapRefreshToken(env, "microsoft-mail", jkt, "microsoft-provider-refresh");
  const target = `${authOrigin}/microsoft-mail/token`;
  const previous = globalThis.fetch;
  let calls = 0;
  let upstreamRefresh;
  globalThis.fetch = async (_url, init) => {
    calls += 1;
    upstreamRefresh = new URLSearchParams(init.body).get("refresh_token");
    assert.equal(init.headers.dpop, undefined);
    return json({ access_token: "refreshed-access", token_type: "Bearer" });
  };
  try {
    const nonce = (await stateRequest(namespace, "microsoft-mail", jkt, "nonce")).body.nonce;
    const success = await onRequestPost({
      env,
      request: request(target, new URLSearchParams({ grant_type: "refresh_token", scope: "offline_access Mail.ReadWrite Mail.Send User.Read", refresh_token: envelope }), await signProof(pair, { htu: target, nonce })),
    });
    assert.equal(success.status, 200);
    const payload = await success.json();
    assert.equal(upstreamRefresh, "microsoft-provider-refresh");
    assert.equal(await unwrapRefreshToken(env, "microsoft-mail", jkt, payload.refresh_token), "microsoft-provider-refresh");
    assert.doesNotMatch(JSON.stringify(payload), /microsoft-provider-refresh/);

    const wrongNonce = (await stateRequest(namespace, "microsoft-mail", otherJkt, "nonce")).body.nonce;
    const wrongKey = await onRequestPost({
      env,
      request: request(target, new URLSearchParams({ grant_type: "refresh_token", scope: "offline_access Mail.ReadWrite Mail.Send User.Read", refresh_token: envelope }), await signProof(otherPair, { htu: target, nonce: wrongNonce })),
    });
    assert.equal(wrongKey.status, 400);

    const rawNonce = (await stateRequest(namespace, "microsoft-mail", jkt, "nonce")).body.nonce;
    const raw = await onRequestPost({
      env,
      request: request(target, new URLSearchParams({ grant_type: "refresh_token", scope: "offline_access Mail.ReadWrite Mail.Send User.Read", refresh_token: "microsoft-provider-refresh" }), await signProof(pair, { htu: target, nonce: rawNonce })),
    });
    assert.equal(raw.status, 400);
    assert.equal(calls, 1);

    await stateRequest(namespace, "microsoft-mail", jkt, "revoke");
    const revokedNonce = (await stateRequest(namespace, "microsoft-mail", jkt, "nonce")).body.nonce;
    const revoked = await onRequestPost({
      env,
      request: request(target, new URLSearchParams({ grant_type: "refresh_token", scope: "offline_access Mail.ReadWrite Mail.Send User.Read", refresh_token: envelope }), await signProof(pair, { htu: target, nonce: revokedNonce })),
    });
    assert.equal(revoked.status, 403);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = previous;
  }
});
test("Microsoft rejects caller client credentials and raw refresh tokens", async () => {
  const namespace = createStateNamespace();
  const env = { ...envTemplate, DPOP_STATE: namespace };
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const target = `${authOrigin}/microsoft-mail/token`;
  const badCredentials = await onRequestPost({
    env,
    request: request(target, new URLSearchParams({ grant_type: "authorization_code", client_id: "caller", client_secret: "caller" }), "bad.proof"),
  });
  assert.equal(badCredentials.status, 400);

  const issued = await namespace.get(namespace.idFromName(`microsoft-mail:${jkt}`)).fetch("https://state.internal", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "nonce" }),
  });
  const nonce = (await issued.json()).nonce;
  const proof = await signProof(pair, { htu: target, nonce });
  const refresh = await onRequestPost({
    env,
    request: request(target, new URLSearchParams({ grant_type: "refresh_token", scope: "offline_access Mail.ReadWrite Mail.Send User.Read", refresh_token: "plain-provider-token" }), proof),
  });
  assert.equal(refresh.status, 400);
});

test("Microsoft disconnect requires a valid envelope, DPoP nonce, and permanently revokes that thumbprint", async () => {
  const namespace = createStateNamespace();
  const env = { ...envTemplate, DPOP_STATE: namespace };
  const pair = await keyPair();
  const jkt = await thumbprint(pair.publicKey);
  const target = `${authOrigin}/microsoft-mail/keys/${jkt}`;
  const envelope = await (await import("../../functions/_shared/token-state.js")).wrapRefreshToken(env, "microsoft-mail", jkt, "ms-refresh-secret");
  const rawProof = await signProof(pair, { htm: "DELETE", htu: target });
  const raw = await revokeRegisteredKey(env, deleteRequest(target, rawProof, "plain-provider-token"), jkt);
  assert.equal(raw.status, 403);

  const challenge = await revokeRegisteredKey(env, deleteRequest(target, rawProof, envelope), jkt);
  assert.equal(challenge.status, 400);
  const nonce = challenge.headers.get("dpop-nonce");
  const proof = await signProof(pair, { htm: "DELETE", htu: target, nonce });
  const response = await revokeRegisteredKey(env, deleteRequest(target, proof, envelope), jkt);
  assert.equal(response.status, 204);
  const stored = await namespace.get(namespace.idFromName(`microsoft-mail:${jkt}`)).fetch("https://state.internal", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "get" }),
  });
  assert.deepEqual(await stored.json(), { revoked: true });
});

function request(url, form, proof) {
  return new Request(url, { method: "POST", headers: { DPoP: proof }, body: form.toString() });
}

function deleteRequest(url, proof, refreshToken) {
  return new Request(url, { method: "DELETE", headers: { DPoP: proof }, body: new URLSearchParams({ refresh_token: refreshToken }) });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
