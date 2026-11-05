import { test } from "node:test";
import assert from "node:assert/strict";
import { onRequestPost } from "../functions/installation/register.js";
import { onRequestPost as rotateInstallation } from "../functions/installation/rotate.js";
import { onRequestPost as startFlow } from "../functions/installation/flow.js";
import { onRequestPost as bindBrowser } from "../functions/installation/bind-browser.js";
import { onRequestPost as browserCandidate } from "../functions/handoff/candidate.js";
import { onRequestPost as authorize } from "../functions/handoff/authorize.js";
import { onRequestPost as callback } from "../functions/handoff/callback.js";
import { onRequestPost as browserStatus } from "../functions/handoff/status.js";
import { onRequestPost as socialExchange } from "../functions/installation/social-exchange.js";
import { onRequestPost as mailExchange } from "../functions/installation/mail-exchange.js";
import { onRequestPost as mailAck } from "../functions/installation/mail-ack.js";
import { onRequestPost as mailStatus } from "../functions/installation/mail-status.js";
import { onRequestPost as mailRefresh } from "../functions/installation/mail-refresh.js";
import { onRequestPost as mailRefreshAck } from "../functions/installation/mail-refresh-ack.js";
import { onRequestPost as mailDisconnect } from "../functions/installation/mail-disconnect.js";
import { onRequestPost as mailCancel } from "../functions/installation/mail-cancel.js";
import { InstallationStateLogic } from "../installation-state/src/state.js";
import { MemoryObjectStorage } from "./helpers/dpop-state.mjs";
import { unwrapRefreshToken } from "../functions/_shared/token-state.js";

const origin = "https://auth.kautuka.io";
const url = `${origin}/installation/register`;
const id = Buffer.alloc(32, 7).toString("base64url");
const enc = (value) => Buffer.from(value).toString("base64url");
async function request(key, body = JSON.stringify({ id }), target = url) {
  const publicKey = await crypto.subtle.exportKey("jwk", key.publicKey);
  const jwk = { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y };
  const time = Math.floor(Date.now() / 1000);
  const header = { typ: "kautuka-installation+jwt", alg: "ES256", jwk };
  const claims = { aud: origin, htm: "POST", htu: target, iat: time, exp: time + 60,
    jti: enc(crypto.getRandomValues(new Uint8Array(32))),
    body_hash: enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))) };
  const input = `${enc(JSON.stringify(header))}.${enc(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(input));
  return new Request(target, { method: "POST", body, headers: { "CF-Connecting-IP": "192.0.2.1",
    "Kautuka-Installation-Proof": `${input}.${enc(signature)}` } });
}

function env() {
  const entries = new Map();
  const limit = { async limit() { return { success: true }; } };
  return { BROKER_ORIGIN: origin, AUTH_TICKET_HMAC_KEY: "test-secret-which-is-longer-than-32-characters", GOOGLE_LOGIN_CLIENT_ID: "google-client",
    GOOGLE_LOGIN_CLIENT_SECRET: "server-secret", MICROSOFT_LOGIN_CLIENT_ID: "microsoft-client", MICROSOFT_LOGIN_CLIENT_SECRET: "server-secret",
    REFRESH_TOKEN_KEYS: JSON.stringify({ active: Buffer.alloc(32, 5).toString("base64") }), REFRESH_TOKEN_ACTIVE_KID: "active",
    MAIL_ACCOUNT_PSEUDONYM_KEY: Buffer.alloc(32, 6).toString("base64"), GOOGLE_CLIENT_ID: "mail-google", GOOGLE_CLIENT_SECRET: "secret",
    MICROSOFT_CLIENT_ID: "mail-ms", MICROSOFT_CLIENT_SECRET: "secret",
    INSTALLATION_REGISTRATION_LIMIT: limit, INSTALLATION_FLOW_LIMIT: limit, INSTALLATION_CONTROL_LIMIT: limit, INVALID_REQUEST_LIMIT: limit, INSTALLATION_POLL_LIMIT: limit, MAIL_REFRESH_LIMIT: limit, HANDOFF_LIMIT: limit, HANDOFF_POLL_LIMIT: limit,
    INSTALLATION_STATE: { idFromName(name) { return name; }, get(name) {
      if (!entries.has(name)) entries.set(name, new InstallationStateLogic({ storage: new MemoryObjectStorage() }));
      return { async fetch(target, init) {
        const input = JSON.parse(init.body);
        if (target.endsWith("/rotate")) return new Response(null, { status: await entries.get(name).rotate(input.oldProof, input.newProof, input.operationId) ? 204 : 409 });
        if (target.endsWith("/cancel-mail-flow") || target.endsWith("/disconnect-mail")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          const ok = target.endsWith("/cancel-mail-flow") ? await state.cancelMailFlow(input.flowId, input.dpopJkt)
            : await state.disconnectMail(input.provider, input.connectionId, input.generation, input.flowId, input.dpopJkt);
          return new Response(null, { status: ok ? 204 : 409 });
        }
        if (target.endsWith("/claim-mail-refresh")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          return Response.json(await state.beginMailRefresh(input));
        }
        if (target.endsWith("/finish-mail-refresh")) return new Response(null, { status: await entries.get(name).finishMailRefresh(input) ? 204 : 409 });
        if (target.endsWith("/fail-mail-refresh-scope")) return new Response(null, { status: await entries.get(name).failMailRefreshScope(input) ? 204 : 409 });
        if (target.endsWith("/read-mail-refresh")) {
          const sealedResult = await entries.get(name).readMailRefresh(input);
          return sealedResult ? Response.json({ sealedResult }) : new Response(null, { status: 409 });
        }
        if (target.endsWith("/ack-mail-refresh")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          return new Response(null, { status: await state.acknowledgeMailRefresh(input) ? 204 : 409 });
        }
        if (target.endsWith("/mail-status")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          return Response.json({ active: await state.wasMailActivated(input.provider, input.connectionId, input.generation, input.flowId, input.dpopJkt) });
        }
        if (target.endsWith("/claim-mail-exchange")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          const cached = await state.readMailExchange(input.flowId, input.verifier, input.dpopJkt);
          if (cached) return Response.json(cached);
          const claim = await state.beginExchange(input.flowId, input.verifier, input.dpopJkt, Date.now(), input.allowedProviders);
          if (claim?.purpose === "mail") return Response.json({ claim });
          const status = await state.mailExchangeStatus(input.flowId, input.verifier, input.dpopJkt);
          if (status?.reason === "insufficient_scope") return Response.json({ code: "insufficient_scope" }, { status: 403 });
          if (status?.reason === "new_account_limit") return Response.json({ code: status.reason, retryAt: status.retryAt, restartRequired: true }, { status: 429 });
          if (status?.reason === "limit") return Response.json({ code: "active_account_limit" }, { status: 409 });
          return new Response(null, { status: status === "pending" ? 202 : status === "failed" ? 410 : 409 });
        }
        if (target.endsWith("/finish-mail-exchange")) {
          const state = entries.get(name);
          if (!await state.verifyFlow(input.flowId, input.account)) return new Response(null, { status: 409 });
          const result = await state.finishMailExchange(input.flowId, input.sealedResult, Date.now(), input.credentialHash, input.credentialEnvelope);
          return Response.json(result.ok ? result : { error: result.reason, retryAt: result.retryAt }, { status: result.ok ? 200 : result.reason === "new_account_limit" ? 429 : 409 });
        }
        if (target.endsWith("/read-mail-result")) {
          const result = await entries.get(name).readMailExchange(input.flowId, input.verifier, input.dpopJkt);
          return result ? Response.json(result) : new Response(null, { status: 409 });
        }
        if (target.endsWith("/ack-mail-exchange")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          if (!await state.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
          return new Response(null, { status: await state.acknowledgeMailExchange(input.flowId, input.verifier, input.dpopJkt) ? 204 : 409 });
        }
        if (target.endsWith("/claim-social-exchange")) {
          const state = entries.get(name);
          if (!await state.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          const sealedResult = await state.readSocialExchange(input.flowId, input.verifier);
          if (sealedResult) return Response.json({ sealedResult });
          const claim = await state.beginExchange(input.flowId, input.verifier, null);
          if (claim && claim.purpose !== "mail") return Response.json({ claim });
          const status = await state.socialExchangeStatus(input.flowId, input.verifier);
          return new Response(null, { status: status === "pending" ? 202 : status === "failed" ? 410 : 409 });
        }
        if (target.endsWith("/finish-social-exchange")) return new Response(null, { status: await entries.get(name).finishSocialExchange(input.flowId, input.sealedResult) ? 204 : 409 });
        if (target.endsWith("/fail-exchange-scope")) return new Response(null, { status: await entries.get(name).failExchangeScope(input.flowId) ? 204 : 409 });
        if (target.endsWith("/fail-exchange")) return new Response(null, { status: await entries.get(name).failExchange(input.flowId) ? 204 : 409 });
        if (target.endsWith("/start-provider")) {
          const result = await entries.get(name).startProvider(input.flowId, input.cookieHash);
          return result ? Response.json(result) : new Response(null, { status: 409 });
        }
        if (target.endsWith("/provider-callback")) {
          const ok = await entries.get(name).recordCallback(input.flowId, input.cookieHash, input.state, input.result);
          return new Response(null, { status: ok ? 204 : 409 });
        }
        if (target.endsWith("/browser-candidate")) {
          const candidate = await entries.get(name).browserCandidate(input.flowId, input.cookieHash);
          return candidate ? Response.json(candidate) : new Response(null, { status: 400 });
        }
        if (target.endsWith("/browser-status")) return Response.json({ status: await entries.get(name).browserStatus(input.flowId, input.cookieHash) });
        if (target.endsWith("/bind-browser")) {
          if (!await entries.get(name).authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          return new Response(null, { status: await entries.get(name).bindBrowser(input.flowId, input.nonce) ? 204 : 409 });
        }
        if (target.endsWith("/create-flow")) {
          if (!await entries.get(name).authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
          const flowId = await entries.get(name).createAuthFlow(input.flow);
          return flowId ? Response.json({ flowId }) : new Response(null, { status: 400 });
        }
        return new Response(null, { status: await entries.get(name).register(input.thumbprint, input.jti, input.expiresAt) ? 204 : 409 });
      } };
    } } };
}

test("signed flow creation rejects public HTTP before creating a flow", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const target = `${origin}/installation/flow`;
  const body = { id, provider: "google", purpose: "login", state: enc(Buffer.alloc(32, 1)),
    challenge: enc(Buffer.alloc(32, 2)), nonce: enc(Buffer.alloc(32, 3)), gatewayOrigin: "http://public.example" };
  assert.equal((await startFlow({ request: await request(key, JSON.stringify(body), target), env: configuration })).status, 400);
  body.gatewayOrigin = "http://192.168.1.20:20229";
  const allowed = await startFlow({ request: await request(key, JSON.stringify(body), target), env: configuration });
  assert.equal(allowed.status, 200);
  assert.match((await allowed.json()).flowId, /^[A-Za-z0-9_-]{43}$/);
});

for (const provider of ["google", "microsoft"]) test(`${provider} mail exchange requires both keys, retrieves a durable provisional result, and acknowledges once`, async () => {
  const configuration = env();
  const installation = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const mailKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = await crypto.subtle.exportKey("jwk", mailKey.publicKey);
  const jwk = { crv: "P-256", kty: "EC", x: publicKey.x, y: publicKey.y };
  const jkt = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(jwk))));
  const signedRequest = async (path, body, key = mailKey) => {
    const target = `${origin}${path}`;
    const signed = await request(installation, JSON.stringify(body), target);
    const pub = await crypto.subtle.exportKey("jwk", key.publicKey);
    const head = enc(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: pub.x, y: pub.y } }));
    const claims = enc(JSON.stringify({ htm: "POST", htu: target, iat: Math.floor(Date.now() / 1000), jti: enc(crypto.getRandomValues(new Uint8Array(32))) }));
    const signature = enc(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(`${head}.${claims}`)));
    const headers = new Headers(signed.headers); headers.set("DPoP", `${head}.${claims}.${signature}`);
    return new Request(signed, { headers });
  };
  assert.equal((await onRequestPost({ request: await request(installation), env: configuration })).status, 204);
  const oauthVerifier = enc(Buffer.alloc(32, 2));
  const challenge = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(oauthVerifier)));
  const oauthState = enc(Buffer.alloc(32, 1));
  const startBody = JSON.stringify({ id, provider, purpose: "mail", state: oauthState, challenge,
    nonce: enc(Buffer.alloc(32, 3)), gatewayOrigin: "http://localhost:20229", connectionId: enc(Buffer.alloc(32, 8)), dpopJkt: jkt, expectedGeneration: 0 });
  const started = await startFlow({ request: await request(installation, startBody, `${origin}/installation/flow`), env: configuration });
  assert.equal(started.status, 200);
  const { flowId } = await started.json();
  configuration.INSTALLATION_FLOW_LIMIT = { async limit() { return { success: false }; } };
  assert.equal((await startFlow({ request: await request(installation, startBody, `${origin}/installation/flow`), env: configuration })).status, 429);
  const browserRequest = (path, body, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const candidate = await browserCandidate({ request: browserRequest("/handoff/candidate", { id, flowId }), env: configuration });
  const cookie = candidate.headers.get("set-cookie").split(";")[0];
  const { nonce } = await candidate.json();
  assert.equal((await bindBrowser({ request: await request(installation, JSON.stringify({ id, flowId, nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
  const authorization = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  const authorizeUrl = new URL((await authorization.json()).authorizeUrl);
  assert.equal(authorizeUrl.hostname, provider === "google" ? "accounts.google.com" : "login.microsoftonline.com");
  assert.ok(authorizeUrl.searchParams.get("scope").includes(provider === "google" ? "https://www.googleapis.com/auth/gmail.modify" : "Mail.ReadWrite"));
  assert.equal(authorizeUrl.searchParams.get("redirect_uri"), `${origin}/callback`);
  const providerState = authorizeUrl.searchParams.get("state");
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state: providerState, code: "provider-code" }, cookie), env: configuration })).status, 204);
  const payload = { id, flowId, verifier: oauthVerifier };
  const otherKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await mailExchange({ request: await signedRequest("/installation/mail-exchange", payload, otherKey), env: configuration })).status, 409);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    assert.equal(init.redirect, "manual");
    if (String(url).endsWith("/token")) {
      assert.equal(new URL(url).hostname, provider === "google" ? "oauth2.googleapis.com" : "login.microsoftonline.com");
      if (init.body.get("grant_type") === "authorization_code") assert.equal(init.body.get("redirect_uri"), `${origin}/callback`);
    }
    return String(url).includes("userinfo") ? Response.json({ sub: "verified-account" })
      : String(url).includes("graph.microsoft.com") ? Response.json({ id: "verified-account" })
      : Response.json({ access_token: "provider-access", refresh_token: "provider-refresh",
        ...(init.body.get("grant_type") === "refresh_token" ? {} : { scope: provider === "google"
          ? "openid https://www.googleapis.com/auth/gmail.modify" : "openid Mail.ReadWrite Mail.Send User.Read" }) });
  };
  try {
    const first = await mailExchange({ request: await signedRequest("/installation/mail-exchange", payload), env: configuration });
    assert.equal(first.status, 200);
    const retryAt = Date.now() + 60000;
    const deniedConfiguration = { ...configuration, INSTALLATION_STATE: { idFromName: name => name, get: () => ({
      fetch: async () => Response.json({ code: "new_account_limit", retryAt, restartRequired: true }, { status: 429 }),
    }) } };
    const denied = await mailExchange({ request: await signedRequest("/installation/mail-exchange", payload), env: deniedConfiguration });
    assert.equal(denied.status, 429);
    assert.equal(denied.headers.get("kautuka-admission-denied"), "new_account_limit");
    assert.equal((await denied.json()).restartRequired, true);
    assert.equal(calls, 2); // A terminal result never calls the provider again.
    const result = await first.json();
    assert.match(result.refreshToken, /^kmf1\./);
    assert.equal(await unwrapRefreshToken(configuration, `${provider}-mail`, jkt, result.refreshToken), null);
    assert.equal(result.access_token, undefined);
    assert.equal((await mailExchange({ request: await signedRequest("/installation/mail-exchange", payload), env: configuration })).status, 200);
    assert.equal(calls, 2);
    const refreshPayload = { id, flowId, provider, connectionId: enc(Buffer.alloc(32, 8)), generation: result.generation,
      operationId: enc(Buffer.alloc(32, 9)), refreshToken: result.refreshToken };
    assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", refreshPayload), env: configuration })).status, 409);
    assert.equal(calls, 2);
    assert.equal((await mailAck({ request: await signedRequest("/installation/mail-ack", payload), env: configuration })).status, 204);
    assert.equal((await mailAck({ request: await signedRequest("/installation/mail-ack", payload), env: configuration })).status, 204);
    const statusPayload = { id, flowId, provider, connectionId: enc(Buffer.alloc(32, 8)), generation: result.generation };
    const status = await mailStatus({ request: await signedRequest("/installation/mail-status", statusPayload), env: configuration });
    assert.deepEqual(await status.json(), { active: true });
    const wrongKeyStatus = await mailStatus({ request: await signedRequest("/installation/mail-status", statusPayload, otherKey), env: configuration });
    assert.deepEqual(await wrongKeyStatus.json(), { active: false });
    assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", refreshPayload, otherKey), env: configuration })).status, 409);
    const firstRefreshRequest = await signedRequest("/installation/mail-refresh", refreshPayload);
    const reusedDpop = firstRefreshRequest.headers.get("DPoP");
    const firstRefresh = await mailRefresh({ request: firstRefreshRequest, env: configuration });
    assert.equal(firstRefresh.status, 200);
    const refreshed = await firstRefresh.json();
    assert.equal(refreshed.accessToken, "provider-access");
    assert.equal(refreshed.expiresAt, null);
    assert.notEqual(refreshed.refreshToken, result.refreshToken);
    const replayBase = await signedRequest("/installation/mail-refresh", refreshPayload);
    const replayHeaders = new Headers(replayBase.headers); replayHeaders.set("DPoP", reusedDpop);
    assert.equal((await mailRefresh({ request: new Request(replayBase, { headers: replayHeaders }), env: configuration })).status, 403);
    const repeated = await mailRefresh({ request: await signedRequest("/installation/mail-refresh", refreshPayload), env: configuration });
    assert.deepEqual(await repeated.json(), refreshed);
    assert.equal(calls, 3);
    const { refreshToken: _discard, ...refreshAckPayload } = refreshPayload;
    const previousRefreshLimit = configuration.MAIL_REFRESH_LIMIT;
    configuration.MAIL_REFRESH_LIMIT = { async limit() { return { success: false }; } };
    assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", refreshPayload), env: configuration })).status, 429);
    assert.equal((await mailRefreshAck({ request: await signedRequest("/installation/mail-refresh-ack", refreshAckPayload), env: configuration })).status, 204);
    assert.equal((await mailRefreshAck({ request: await signedRequest("/installation/mail-refresh-ack", refreshAckPayload), env: configuration })).status, 204);
    configuration.MAIL_REFRESH_LIMIT = previousRefreshLimit;
    // A redirect during refresh must not forward credentials to its target.
    // The failed operation remains uncertain and must not be retried upstream.
    const uncertainRefresh = { ...refreshPayload, refreshToken: refreshed.refreshToken, operationId: enc(Buffer.alloc(32, 10)) };
    const providerFetch = globalThis.fetch, realNow = Date.now;
    let uncertainCalls = 0;
    globalThis.fetch = async (_url, init) => { uncertainCalls++; assert.equal(init.redirect, "manual"); return new Response(null, { status: 302, headers: { location: "https://attacker.example/" } }); };
    try {
      assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", uncertainRefresh), env: configuration })).status, 503);
      assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", uncertainRefresh), env: configuration })).status, 202);
      const future = realNow() + 31_000;
      Date.now = () => future;
      assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", uncertainRefresh), env: configuration })).status, 410);
      assert.equal(uncertainCalls, 1);
    } finally { globalThis.fetch = providerFetch; Date.now = realNow; }
    assert.equal((await mailCancel({ request: await signedRequest("/installation/mail-cancel", { id, flowId }), env: configuration })).status, 409);
    assert.equal((await mailDisconnect({ request: await signedRequest("/installation/mail-disconnect", statusPayload, otherKey), env: configuration })).status, 409);
    assert.equal((await mailDisconnect({ request: await signedRequest("/installation/mail-disconnect", statusPayload), env: configuration })).status, 204);
    assert.equal((await mailDisconnect({ request: await signedRequest("/installation/mail-disconnect", statusPayload), env: configuration })).status, 204);
    assert.equal((await mailRefresh({ request: await signedRequest("/installation/mail-refresh", { ...refreshPayload, refreshToken: refreshed.refreshToken,
      operationId: enc(Buffer.alloc(32, 11)) }), env: configuration })).status, 409);
  } finally { globalThis.fetch = originalFetch; }
});

test("sixth verified mailbox is denied through the broker without replaying its provider code", async () => {
  const configuration = env();
  const installation = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const mailKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", mailKey.publicKey);
  const jwk = { crv: "P-256", kty: "EC", x: pub.x, y: pub.y };
  const jkt = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(jwk))));
  const signedMail = async (path, payload) => {
    const target = `${origin}${path}`;
    const signed = await request(installation, JSON.stringify(payload), target);
    const head = enc(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk }));
    const claims = enc(JSON.stringify({ htm: "POST", htu: target, iat: Math.floor(Date.now() / 1000), jti: enc(crypto.getRandomValues(new Uint8Array(32))) }));
    const signature = enc(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mailKey.privateKey, new TextEncoder().encode(`${head}.${claims}`)));
    const headers = new Headers(signed.headers); headers.set("DPoP", `${head}.${claims}.${signature}`);
    return new Request(signed, { headers });
  };
  assert.equal((await onRequestPost({ request: await request(installation), env: configuration })).status, 204);
  const verifier = enc(Buffer.alloc(32, 2));
  const challenge = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const browser = (path, payload, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: { origin,
    "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(payload) });
  const originalFetch = globalThis.fetch;
  let providerCalls = 0, currentAccount = 0;
  globalThis.fetch = async value => {
    providerCalls++;
    return String(value).includes("userinfo") ? Response.json({ sub: `account-${currentAccount}` })
      : Response.json({ access_token: "provider-access", refresh_token: "provider-refresh", scope: "https://www.googleapis.com/auth/gmail.modify" });
  };
  try {
    for (let n = 0; n < 6; n++) {
      currentAccount = n;
      const startBody = JSON.stringify({ id, provider: "google", purpose: "mail", state: enc(Buffer.alloc(32, 20 + n)), challenge,
        nonce: enc(Buffer.alloc(32, 40 + n)), gatewayOrigin: "http://localhost:20229", connectionId: enc(Buffer.alloc(32, 60 + n)), dpopJkt: jkt, expectedGeneration: 0 });
      const flow = await startFlow({ request: await request(installation, startBody, `${origin}/installation/flow`), env: configuration });
      const { flowId } = await flow.json();
      const candidate = await browserCandidate({ request: browser("/handoff/candidate", { id, flowId }), env: configuration });
      const cookie = candidate.headers.get("set-cookie").split(";")[0], nonce = (await candidate.json()).nonce;
      assert.equal((await bindBrowser({ request: await request(installation, JSON.stringify({ id, flowId, nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
      const authorized = await authorize({ request: browser("/handoff/authorize", { id, flowId }, cookie), env: configuration });
      const state = new URL((await authorized.json()).authorizeUrl).searchParams.get("state");
      assert.equal((await callback({ request: browser("/handoff/callback", { state, code: `provider-code-${n}` }, cookie), env: configuration })).status, 204);
      const payload = { id, flowId, verifier };
      const result = await mailExchange({ request: await signedMail("/installation/mail-exchange", payload), env: configuration });
      if (n < 5) {
        assert.equal(result.status, 200);
        assert.equal((await mailAck({ request: await signedMail("/installation/mail-ack", payload), env: configuration })).status, 204);
      } else {
        assert.equal(result.status, 409);
        assert.equal(result.headers.get("kautuka-admission-denied"), "active_account_limit");
        const before = providerCalls;
        const retry = await mailExchange({ request: await signedMail("/installation/mail-exchange", payload), env: configuration });
        assert.equal(retry.status, 409);
        assert.equal(retry.headers.get("kautuka-admission-denied"), "active_account_limit");
        assert.equal(providerCalls, before);
      }
    }
  } finally { globalThis.fetch = originalFetch; }
});

test("rotation requires both installation keys and rejects the old key afterwards", async () => {
  const configuration = env();
  const oldKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const newKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const attackerKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(oldKey), env: configuration })).status, 204);
  const publicKey = await crypto.subtle.exportKey("jwk", newKey.publicKey);
  const canonical = JSON.stringify({ crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x, y: publicKey.y });
  const replacementThumbprint = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
  const target = `${origin}/installation/rotate`, body = JSON.stringify({ id, operationId: enc(Buffer.alloc(32, 12)), replacementThumbprint });
  const rotation = async (old, replacement) => {
    const signed = await request(old, body, target);
    const replacementSigned = await request(replacement, body, target);
    const headers = new Headers(signed.headers);
    headers.set("Kautuka-Replacement-Proof", replacementSigned.headers.get("Kautuka-Installation-Proof"));
    return new Request(signed, { headers });
  };
  assert.equal((await rotateInstallation({ request: await request(oldKey, body, target), env: configuration })).status, 400);
  assert.equal((await rotateInstallation({ request: await rotation(oldKey, attackerKey), env: configuration })).status, 400);
  assert.equal((await rotateInstallation({ request: await rotation(oldKey, newKey), env: configuration })).status, 204);
  assert.equal((await rotateInstallation({ request: await rotation(oldKey, newKey), env: configuration })).status, 204);
  assert.equal((await onRequestPost({ request: await request(oldKey), env: configuration })).status, 409);
  assert.equal((await onRequestPost({ request: await request(newKey), env: configuration })).status, 204);
});

test("registration binds an installation ID to its proof key and rejects replay or takeover", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const first = await request(key);
  assert.equal((await onRequestPost({ request: first.clone(), env: configuration })).status, 204);
  assert.equal((await onRequestPost({ request: first, env: configuration })).status, 409);
  assert.equal((await onRequestPost({ request: await request(other), env: configuration })).status, 409);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
});

for (const provider of ["google", "microsoft"]) test(`${provider} social exchange returns an installation-bound cached identity token without repeating provider exchange`, async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = (n) => Buffer.alloc(32, n).toString("base64url");
  const verifier = encoded(2);
  const challenge = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const startBody = JSON.stringify({ id, provider, purpose: "login", state: encoded(1), challenge,
    nonce: encoded(3), gatewayOrigin: "http://localhost:20229" });
  const started = await startFlow({ request: await request(key, startBody, `${origin}/installation/flow`), env: configuration });
  const { flowId } = await started.json();
  const browserRequest = (path, body, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const candidate = await browserCandidate({ request: browserRequest("/handoff/candidate", { id, flowId }), env: configuration });
  const cookie = candidate.headers.get("set-cookie").split(";")[0];
  const { nonce } = await candidate.json();
  assert.equal((await bindBrowser({ request: await request(key, JSON.stringify({ id, flowId, nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
  const authorized = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  const authorizeUrl = new URL((await authorized.json()).authorizeUrl);
  assert.equal(authorizeUrl.hostname, provider === "google" ? "accounts.google.com" : "login.microsoftonline.com");
  assert.equal(authorizeUrl.searchParams.get("redirect_uri"), `${origin}/callback`);
  const providerState = authorizeUrl.searchParams.get("state");
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state: providerState, code: "one-use-code" }, cookie), env: configuration })).status, 204);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    assert.equal(init.redirect, "manual");
    assert.equal(new URL(url).hostname, provider === "google" ? "oauth2.googleapis.com" : "login.microsoftonline.com");
    assert.equal(init.body.get("redirect_uri"), `${origin}/callback`);
    return Response.json({ id_token: "test-identity-token-value-long-enough" });
  };
  try {
    const body = JSON.stringify({ id, flowId, verifier });
    const target = `${origin}/installation/social-exchange`;
    const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    assert.equal((await socialExchange({ request: await request(other, body, target), env: configuration })).status, 403);
    assert.equal((await socialExchange({ request: await request(key, JSON.stringify({ id, flowId, verifier: encoded(9) }), target), env: configuration })).status, 409);
    const first = await socialExchange({ request: await request(key, body, target), env: configuration });
    assert.equal(first.status, 200);
    assert.equal((await first.json()).id_token, "test-identity-token-value-long-enough");
    const retry = await socialExchange({ request: await request(key, body, target), env: configuration });
    assert.equal(retry.status, 200);
    assert.equal((await retry.json()).id_token, "test-identity-token-value-long-enough");
    assert.equal(calls, 1);
  } finally { globalThis.fetch = originalFetch; }
});

for (const provider of ["google", "microsoft"]) for (const purpose of ["login", "mail"]) for (const outcome of ["denied", "lost-response", "provider-redirect", ...(purpose === "login" ? ["provider-rejected"] : [])]) test(`${provider} ${purpose} ${outcome} is terminal`, async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const mailKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", mailKey.publicKey);
  const jwk = { crv: "P-256", kty: "EC", x: pub.x, y: pub.y };
  const jkt = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(jwk))));
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const verifier = enc(Buffer.alloc(32, 2));
  const challenge = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const body = { id, provider, purpose, state: enc(Buffer.alloc(32, 1)), challenge,
    nonce: enc(Buffer.alloc(32, 3)), gatewayOrigin: "http://localhost:20229",
    ...(purpose === "mail" ? { connectionId: enc(Buffer.alloc(32, 8)), dpopJkt: jkt, expectedGeneration: 0 } : {}) };
  const started = await startFlow({ request: await request(key, JSON.stringify(body), `${origin}/installation/flow`), env: configuration });
  assert.equal(started.status, 200);
  const { flowId } = await started.json();
  const browserRequest = (path, value, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(value) });
  const candidate = await browserCandidate({ request: browserRequest("/handoff/candidate", { id, flowId }), env: configuration });
  const cookie = candidate.headers.get("set-cookie").split(";")[0];
  const { nonce } = await candidate.json();
  assert.equal((await bindBrowser({ request: await request(key, JSON.stringify({ id, flowId, nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
  const authorized = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  const state = new URL((await authorized.json()).authorizeUrl).searchParams.get("state");
  assert.equal((await callback({ request: browserRequest("/handoff/callback", outcome === "denied" ? { state, error: "access_denied" } : { state, code: "one-use-code" }, cookie), env: configuration })).status, 204);
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "late-code" }, cookie), env: configuration })).status, 409);
  const target = `${origin}/installation/${purpose === "mail" ? "mail" : "social"}-exchange`;
  const exchangeRequest = async () => {
    const signed = await request(key, JSON.stringify({ id, flowId, verifier }), target);
    const headers = new Headers(signed.headers);
    if (purpose === "mail") {
      const head = enc(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk }));
      const claims = enc(JSON.stringify({ htm: "POST", htu: target, iat: Math.floor(Date.now() / 1000), jti: enc(crypto.getRandomValues(new Uint8Array(32))) }));
      const signature = enc(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mailKey.privateKey, new TextEncoder().encode(`${head}.${claims}`)));
      headers.set("DPoP", `${head}.${claims}.${signature}`);
    }
    return new Request(signed, { headers });
  };
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (_url, init) => { calls++; assert.equal(init.redirect, "manual"); if (outcome === "provider-redirect") return new Response(null, { status: 302, headers: { location: "https://attacker.example/" } }); if (outcome === "provider-rejected") return new Response("sensitive provider detail", { status: 400 }); throw new Error("provider response unavailable"); };
  try {
    const exchange = purpose === "mail" ? mailExchange : socialExchange;
    const first = await exchange({ request: await exchangeRequest(), env: configuration });
    assert.equal(first.status, outcome === "denied" ? 410 : purpose === "login" && ["provider-rejected", "provider-redirect"].includes(outcome) ? 502 : 503);
    assert.doesNotMatch(await first.text(), /sensitive provider detail/);
    assert.equal((await exchange({ request: await exchangeRequest(), env: configuration })).status, 410);
    assert.equal(calls, outcome === "denied" ? 0 : 1);
  } finally { globalThis.fetch = originalFetch; }
});

test("an ambiguous provider exchange is never retried automatically", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = (n) => Buffer.alloc(32, n).toString("base64url");
  const verifier = encoded(2);
  const challenge = enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const startBody = JSON.stringify({ id, provider: "google", purpose: "login", state: encoded(1), challenge,
    nonce: encoded(3), gatewayOrigin: "http://localhost:20229" });
  const started = await startFlow({ request: await request(key, startBody, `${origin}/installation/flow`), env: configuration });
  const { flowId } = await started.json();
  const browserRequest = (path, body, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const candidate = await browserCandidate({ request: browserRequest("/handoff/candidate", { id, flowId }), env: configuration });
  const cookie = candidate.headers.get("set-cookie").split(";")[0];
  const { nonce } = await candidate.json();
  assert.equal((await bindBrowser({ request: await request(key, JSON.stringify({ id, flowId, nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
  const authorized = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  const state = new URL((await authorized.json()).authorizeUrl).searchParams.get("state");
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "one-use-code" }, cookie), env: configuration })).status, 204);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error("provider response lost"); };
  try {
    const body = JSON.stringify({ id, flowId, verifier });
    const target = `${origin}/installation/social-exchange`;
    assert.equal((await socialExchange({ request: await request(key, body, target), env: configuration })).status, 503);
    assert.equal((await socialExchange({ request: await request(key, body, target), env: configuration })).status, 410);
    assert.equal(calls, 1);
  } finally { globalThis.fetch = originalFetch; }
});

test("bound browser completes provider callback; stolen cookie or altered state is rejected", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = (n) => Buffer.alloc(32, n).toString("base64url");
  const startBody = JSON.stringify({ id, provider: "google", purpose: "login", state: encoded(1), challenge: encoded(2),
    nonce: encoded(3), gatewayOrigin: "http://localhost:20229" });
  const started = await startFlow({ request: await request(key, startBody, `${origin}/installation/flow`), env: configuration });
  const { flowId } = await started.json();
  const browserRequest = (path, body, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const candidate = await browserCandidate({ request: browserRequest("/handoff/candidate", { id, flowId }), env: configuration });
  const cookie = candidate.headers.get("set-cookie").split(";")[0];
  const { nonce } = await candidate.json();
  const waiting = await browserStatus({ request: browserRequest("/handoff/status", { id, flowId }, cookie), env: configuration });
  assert.equal((await waiting.json()).status, "waiting");
  const before = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  assert.equal(before.status, 409);
  const body = JSON.stringify({ id, flowId, nonce });
  assert.equal((await bindBrowser({ request: await request(key, body, `${origin}/installation/bind-browser`), env: configuration })).status, 204);
  const ready = await browserStatus({ request: browserRequest("/handoff/status", { id, flowId }, cookie), env: configuration });
  assert.equal((await ready.json()).status, "ready");
  const authorized = await authorize({ request: browserRequest("/handoff/authorize", { id, flowId }, cookie), env: configuration });
  assert.equal(authorized.status, 200);
  const providerUrl = new URL((await authorized.json()).authorizeUrl);
  assert.equal(providerUrl.origin, "https://accounts.google.com");
  assert.equal(providerUrl.searchParams.get("redirect_uri"), `${origin}/callback`);
  const state = providerUrl.searchParams.get("state");
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "code" }, `__Host-kautuka-broker-${flowId}=${encoded(9)}`), env: configuration })).status, 409);
  const stateParts = state.split(".");
  stateParts[4] = (stateParts[4][0] === "A" ? "B" : "A") + stateParts[4].slice(1);
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state: stateParts.join("."), code: "code" }, cookie), env: configuration })).status, 400);
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "code" }, cookie), env: configuration })).status, 204);
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "code" }, cookie), env: configuration })).status, 204);
  assert.equal((await callback({ request: browserRequest("/handoff/callback", { state, code: "other-code" }, cookie), env: configuration })).status, 409);
});

test("only installation owner can bind the broker browser candidate", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = (n) => Buffer.alloc(32, n).toString("base64url");
  const startBody = JSON.stringify({ id, provider: "google", purpose: "login", state: encoded(1), challenge: encoded(2),
    nonce: encoded(3), gatewayOrigin: "http://localhost:20229" });
  const started = await startFlow({ request: await request(key, startBody, `${origin}/installation/flow`), env: configuration });
  const { flowId } = await started.json();
  const candidateRequest = () => new Request(`${origin}/handoff/candidate`, { method: "POST", headers: { origin,
    "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1" }, body: JSON.stringify({ id, flowId }) });
  const candidate = await browserCandidate({ request: candidateRequest(), env: configuration });
  assert.equal(candidate.status, 200);
  assert.match(candidate.headers.get("set-cookie"), /^__Host-kautuka-broker-[A-Za-z0-9_-]{43}=.*; Path=\/; Max-Age=300; Secure; HttpOnly; SameSite=Lax$/);
  const { nonce } = await candidate.json();
  const body = JSON.stringify({ id, flowId, nonce });
  const target = `${origin}/installation/bind-browser`;
  assert.equal((await bindBrowser({ request: await request(other, body, target), env: configuration })).status, 403);
  assert.equal((await bindBrowser({ request: await request(key, body, target), env: configuration })).status, 204);
  assert.equal((await browserCandidate({ request: candidateRequest(), env: configuration })).status, 400);
});

test("simultaneous first-use flows keep independent browser cookies", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = n => Buffer.alloc(32, n).toString("base64url");
  const flows = [];
  for (const n of [1, 2]) {
    const body = JSON.stringify({ id, provider: "google", purpose: "login", state: encoded(n), challenge: encoded(3), nonce: encoded(4), gatewayOrigin: "http://localhost:20229" });
    flows.push((await (await startFlow({ request: await request(key, body, `${origin}/installation/flow`), env: configuration })).json()).flowId);
  }
  const browser = (path, body, cookie) => new Request(`${origin}${path}`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const candidates = await Promise.all(flows.map(flowId => browserCandidate({ request: browser("/handoff/candidate", { id, flowId }), env: configuration })));
  const cookies = candidates.map(candidate => candidate.headers.get("set-cookie").split(";")[0]);
  assert.notEqual(cookies[0].split("=")[0], cookies[1].split("=")[0]);
  for (let i = 0; i < flows.length; i++) {
    const nonce = (await candidates[i].json()).nonce;
    assert.equal((await bindBrowser({ request: await request(key, JSON.stringify({ id, flowId: flows[i], nonce }), `${origin}/installation/bind-browser`), env: configuration })).status, 204);
    assert.equal((await authorize({ request: browser("/handoff/authorize", { id, flowId: flows[i] }, cookies.join("; ")), env: configuration })).status, 200);
  }
});

test("browser candidates reject cross-origin posts and invalid duplicate cookies", async () => {
  const configuration = env();
  const body = JSON.stringify({ id, flowId: Buffer.alloc(32, 8).toString("base64url") });
  const candidate = (extra) => new Request(`${origin}/handoff/candidate`, { method: "POST", headers: {
    origin, "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1", ...extra }, body });
  assert.equal((await browserCandidate({ request: candidate({ origin: "https://attacker.invalid" }), env: configuration })).status, 400);
  const cookieName = `__Host-kautuka-broker-${Buffer.alloc(32, 8).toString("base64url")}`;
  assert.equal((await browserCandidate({ request: candidate({ cookie: `${cookieName}=${id}; ${cookieName}=${id}` }), env: configuration })).status, 400);
});

test("only registered installation key can create a flow and replay is rejected", async () => {
  const configuration = env();
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const encoded = (n) => Buffer.alloc(32, n).toString("base64url");
  const body = JSON.stringify({ id, provider: "google", purpose: "login", state: encoded(1), challenge: encoded(2),
    nonce: encoded(3), gatewayOrigin: "http://localhost:20229" });
  const target = `${origin}/installation/flow`;
  const attempt = await request(key, body, target);
  const accepted = await startFlow({ request: attempt.clone(), env: configuration });
  assert.equal(accepted.status, 200);
  assert.match((await accepted.json()).flowId, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await startFlow({ request: attempt, env: configuration })).status, 403);
  assert.equal((await startFlow({ request: await request(other, body, target), env: configuration })).status, 403);
});

test("missing mailbox pseudonym key blocks mail without blocking social sign-in", async () => {
  const configuration = env();
  delete configuration.MAIL_ACCOUNT_PSEUDONYM_KEY;
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const common = { id, provider: "google", state: enc(Buffer.alloc(32, 1)), challenge: enc(Buffer.alloc(32, 2)),
    nonce: enc(Buffer.alloc(32, 3)), gatewayOrigin: "http://localhost:20229" };
  const target = `${origin}/installation/flow`;
  const mail = { ...common, purpose: "mail", connectionId: enc(Buffer.alloc(32, 4)), dpopJkt: enc(Buffer.alloc(32, 5)), expectedGeneration: 0 };
  assert.equal((await startFlow({ request: await request(key, JSON.stringify(mail), target), env: configuration })).status, 503);
  assert.equal((await startFlow({ request: await request(key, JSON.stringify({ ...common, purpose: "login" }), target), env: configuration })).status, 200);
});

test("registration fails closed when rate limiting is absent, denies or fails", async () => {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const configuration = env();
  delete configuration.INSTALLATION_REGISTRATION_LIMIT;
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 503);
  configuration.INSTALLATION_REGISTRATION_LIMIT = { async limit() { return { success: false }; } };
  const rejected = await onRequestPost({ request: await request(key), env: configuration });
  assert.equal(rejected.status, 429);
  assert.equal(rejected.headers.get("retry-after"), "60");
  configuration.INSTALLATION_REGISTRATION_LIMIT = { async limit() { throw new Error("offline"); } };
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 503);
});

test("invalid proof budget is separate from successful registration", async () => {
  const configuration = env();
  let failures = 0;
  configuration.INVALID_REQUEST_LIMIT = { async limit() { return { success: ++failures <= 1 }; } };
  const invalid = () => new Request(url, { method: "POST", body: JSON.stringify({ id }), headers: { "CF-Connecting-IP": "192.0.2.1" } });
  assert.equal((await onRequestPost({ request: invalid(), env: configuration })).status, 400);
  assert.equal((await onRequestPost({ request: invalid(), env: configuration })).status, 429);
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
});

test("replayed valid installation proofs consume the invalid-request budget", async () => {
  const configuration = env();
  let failures = 0;
  configuration.INVALID_REQUEST_LIMIT = { async limit() { return { success: ++failures <= 1 }; } };
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  assert.equal((await onRequestPost({ request: await request(key), env: configuration })).status, 204);
  const token = n => enc(Buffer.alloc(32, n));
  const body = JSON.stringify({ id, provider: "google", purpose: "login", state: token(1), challenge: token(2), nonce: token(3), gatewayOrigin: "http://localhost:20229" });
  const target = `${origin}/installation/flow`;
  const signed = await request(key, body, target);
  assert.equal((await startFlow({ request: signed.clone(), env: configuration })).status, 200);
  assert.equal((await startFlow({ request: signed.clone(), env: configuration })).status, 403);
  assert.equal((await startFlow({ request: signed.clone(), env: configuration })).status, 429);
  assert.equal((await startFlow({ request: await request(key, body, target), env: configuration })).status, 200);
});
