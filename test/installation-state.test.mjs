import { test } from "node:test";
import assert from "node:assert/strict";
import { InstallationStateLogic } from "../installation-state/src/state.js";
import { MemoryObjectStorage } from "./helpers/dpop-state.mjs";

const id = (number) => Buffer.alloc(32, number).toString("base64url");
const verifier = id(2);
const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
let nextState = 1;
const states = new Map();
const sealedResult = "sealed." + "x".repeat(40);
const credential = "kmf1.initial.encrypted";
const nextCredential = "kmf1.next.encrypted";
const hashEnvelope = async (value) => encHash(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
const encHash = (bytes) => Buffer.from(bytes).toString("base64url");
const credentialHash = await hashEnvelope(credential);
const nextCredentialHash = await hashEnvelope(nextCredential);
class TestInstallationState extends InstallationStateLogic {
  finishMailExchange(flow, result, now, hash = credentialHash) { return super.finishMailExchange(flow, result, now, hash, credential); }
  async admit(flow, now) {
    const result = await this.finishMailExchange(flow, sealedResult, now);
    if (result.ok) assert.equal(await this.acknowledgeMailExchange(flow, verifier, id(5), now), true);
    return result;
  }
}
async function initialized(storage = new MemoryObjectStorage()) {
  const state = new TestInstallationState({ storage });
  assert.equal(await state.register(id(250), id(251), Date.now() + 60000), true);
  return state;
}
async function start(state, provider, connection, expectedGeneration = 0) {
  const oauthState = id(nextState++ % 240);
  const flow = await state.createAuthFlow({ provider, purpose: "mail", state: oauthState, challenge, nonce: id(3),
    gatewayOrigin: "http://localhost:20229", connectionId: id(connection), dpopJkt: id(5), expectedGeneration });
  assert.ok(flow);
  states.set(flow, oauthState);
  return flow;
}
async function prepare(state, provider, account, connection, expectedGeneration = 0) {
  const flow = await start(state, provider, connection, expectedGeneration);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), states.get(flow), { code: "provider-code" }), true);
  assert.ok(await state.beginExchange(flow, verifier, id(5)));
  assert.equal(await state.verifyFlow(flow, id(account)), true);
  return flow;
}

test("mail exchange cannot consume a social code and unavailable providers cannot consume a mail code", async () => {
  const state = await initialized();
  const flow = await state.createAuthFlow({ provider: "google", purpose: "login", state: id(239), challenge,
    nonce: id(3), gatewayOrigin: "http://localhost:20229" });
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), id(239), { code: "social-code" }), true);
  assert.equal(await state.beginExchange(flow, verifier, id(5)), null);
  assert.ok(await state.beginExchange(flow, verifier, null));
  const mail = await start(state, "google", 20);
  const mailBrowser = await state.browserCandidate(mail, id(10));
  assert.equal(await state.bindBrowser(mail, mailBrowser.nonce), true);
  assert.ok(await state.startProvider(mail, id(10)));
  assert.equal(await state.recordCallback(mail, id(10), states.get(mail), { code: "mail-code" }), true);
  assert.equal(await state.beginExchange(mail, verifier, id(5), Date.now(), ["microsoft"]), null);
  assert.ok(await state.beginExchange(mail, verifier, id(5), Date.now(), ["google"]));
});

test("atomic admission caps distinct accounts and allows the same account twice", async () => {
  const state = await initialized();
  const flows = [];
  for (let n = 0; n < 6; n++) flows.push(await prepare(state, "google", n, n + 20));
  const results = await Promise.all(flows.map((flow) => state.admit(flow)));
  assert.equal(results.filter((result) => result.ok).length, 5);
  assert.equal(results.filter((result) => result.reason === "limit").length, 1);
  const rejected = flows[results.findIndex(result => result.reason === "limit")];
  assert.equal((await state.mailExchangeStatus(rejected, verifier, id(5))).reason, "limit");
  assert.equal(await state.beginExchange(rejected, verifier, id(5)), null);
  assert.equal((await state.admit(await prepare(state, "google", 0, 40))).ok, true);
  assert.equal((await state.admit(await prepare(state, "microsoft", 5, 41))).ok, true);
});

test("rolling new-account limit survives disconnect and makes denial terminal", async () => {
  const storage = new MemoryObjectStorage();
  const state = new TestInstallationState({ storage }, { newAccountLimit: 2, newAccountWindowSeconds: 60 });
  assert.equal(await state.register(id(250), id(251), Date.now() + 60000), true);
  const first = await state.admit(await prepare(state, "google", 1, 20));
  assert.equal(await state.disconnect("google", id(20), first.generation), true);
  const second = await state.admit(await prepare(state, "google", 2, 21));
  assert.equal(await state.disconnect("google", id(21), second.generation), true);
  assert.equal((await state.admit(await prepare(state, "google", 1, 22))).ok, true);
  const deniedFlow = await prepare(state, "google", 3, 23);
  const denied = await state.finishMailExchange(deniedFlow, sealedResult);
  assert.equal(denied.reason, "new_account_limit");
  assert.ok(denied.retryAt > Date.now());
  assert.deepEqual(await state.mailExchangeStatus(deniedFlow, verifier, id(5)), { reason: "new_account_limit", retryAt: denied.retryAt });
  assert.equal(await state.beginExchange(deniedFlow, verifier, id(5)), null);
  assert.equal((await state.admit(await prepare(state, "microsoft", 3, 24))).ok, true);
  const history = await storage.get('account-history:google');
  await storage.put('account-history:google', history.map(entry => ({ ...entry, at: Date.now() - 60001 })));
  assert.equal((await state.admit(await prepare(state, "google", 3, 25))).ok, true);
});

test("concurrent new-account admissions atomically share the rolling budget", async () => {
  const state = new TestInstallationState({ storage: new MemoryObjectStorage() }, { newAccountLimit: 1, newAccountWindowSeconds: 60 });
  assert.equal(await state.register(id(250), id(251), Date.now() + 60000), true);
  const first = await prepare(state, "google", 7, 27);
  const second = await prepare(state, "google", 8, 28);
  const results = await Promise.all([state.finishMailExchange(first, sealedResult), state.finishMailExchange(second, sealedResult)]);
  assert.equal(results.filter(result => result.ok).length, 1);
  assert.equal(results.filter(result => result.reason === "new_account_limit").length, 1);
});

test("mail admission and sealed result survive a lost response, but not disconnect", async () => {
  const storage = new MemoryObjectStorage();
  const state = await initialized(storage);
  const flow = await prepare(state, "google", 1, 20);
  const admitted = await state.finishMailExchange(flow, sealedResult);
  assert.equal(admitted.ok, true);
  const restored = new TestInstallationState({ storage });
  assert.deepEqual(await restored.finishMailExchange(flow, sealedResult), admitted);
  assert.equal((await restored.finishMailExchange(flow, "sealed." + "y".repeat(40))).ok, false);
  assert.deepEqual(await restored.readMailExchange(flow, verifier, id(5)), { sealedResult, generation: admitted.generation });
  assert.equal(await restored.readMailExchange(flow, id(8), id(5)), null);
  assert.equal(await restored.readMailExchange(flow, verifier, id(8)), null);
  assert.equal(await restored.acknowledgeMailExchange(flow, verifier, id(5)), true);
  assert.equal(await restored.acknowledgeMailExchange(flow, verifier, id(5)), true);
  assert.equal(await restored.cancelFlow(flow), false);
  await restored.sweepExpired(Date.now() + 301_000);
  assert.equal(await restored.wasMailActivated("google", id(20), admitted.generation, flow, id(5)), true);
  assert.equal(await restored.wasMailActivated("google", id(20), admitted.generation, id(9), id(5)), false);
  assert.equal(await restored.disconnect("google", id(20), admitted.generation), true);
  assert.equal(await restored.readMailExchange(flow, verifier, id(5)), null);
  assert.equal((await restored.finishMailExchange(flow, sealedResult)).ok, false);
});

test("an unacknowledged replacement expires without changing the existing connection", async () => {
  const state = await initialized();
  const initial = await state.admit(await prepare(state, "google", 1, 20));
  const replacementFlow = await prepare(state, "google", 1, 20, initial.generation);
  const replacement = await state.finishMailExchange(replacementFlow, sealedResult);
  assert.equal(replacement.ok, true);
  assert.equal(await state.isActive("google", id(20), initial.generation), true);
  assert.equal(await state.isActive("google", id(20), replacement.generation), false);
  await state.sweepExpired(Date.now() + 301_000);
  assert.equal(await state.isActive("google", id(20), initial.generation), true);
  assert.equal(await state.acknowledgeMailExchange(replacementFlow, verifier, id(5)), false);
});

test("refresh serializes provider calls and retains a rotated result until acknowledged", async () => {
  const state = await initialized();
  const flowId = await prepare(state, "google", 1, 20);
  const active = await state.admit(flowId);
  const input = { provider: "google", connection: id(20), generation: active.generation, flowId,
    dpopJkt: id(5), operationId: id(80), credentialHash };
  const claims = await Promise.all([state.beginMailRefresh(input), state.beginMailRefresh(input)]);
  assert.deepEqual(claims.map((claim) => claim.status).sort(), ["busy", "claimed"]);
  assert.equal((await state.beginMailRefresh({ ...input, flowId: id(9) })).status, "invalid");
  assert.equal(await state.finishMailRefresh({ ...input, nextCredentialHash: credentialHash, nextCredentialEnvelope: credential, sealedResult }), false);
  assert.equal(await state.finishMailRefresh({ ...input, nextCredentialHash, nextCredentialEnvelope: nextCredential, sealedResult }), true);
  assert.deepEqual(await state.beginMailRefresh(input), { status: "complete", sealedResult });
  assert.equal((await state.beginMailRefresh({ ...input, operationId: id(81), credentialHash: nextCredentialHash })).status, "busy");
  assert.equal(await state.acknowledgeMailRefresh(input), true);
  assert.equal(await state.acknowledgeMailRefresh(input), true);
  assert.equal((await state.beginMailRefresh({ ...input, operationId: id(81) })).status, "invalid");
  assert.equal((await state.beginMailRefresh({ ...input, operationId: id(81), credentialHash: nextCredentialHash })).status, "claimed");
});

test("an uncertain or disconnected refresh never publishes a late result", async () => {
  const state = await initialized();
  const flowId = await prepare(state, "google", 1, 20);
  const active = await state.admit(flowId);
  const input = { provider: "google", connection: id(20), generation: active.generation, flowId,
    dpopJkt: id(5), operationId: id(80), credentialHash };
  const now = Date.now();
  assert.equal((await state.beginMailRefresh(input, now)).status, "claimed");
  assert.equal((await state.beginMailRefresh(input, now + 30_000)).status, "unknown");
  assert.equal(await state.finishMailRefresh({ ...input, nextCredentialHash, nextCredentialEnvelope: nextCredential, sealedResult }, now + 30_001), false);
  assert.equal(await state.disconnect("google", id(20), active.generation), true);
  assert.equal((await state.beginMailRefresh(input)).status, "invalid");
  assert.equal(await state.finishMailRefresh({ ...input, nextCredentialHash, nextCredentialEnvelope: nextCredential, sealedResult }), false);
});

test("partial refresh scopes are terminal only for the exact active operation", async () => {
  const storage = new MemoryObjectStorage();
  const state = await initialized(storage);
  const flowId = await prepare(state, "google", 1, 20);
  const active = await state.admit(flowId);
  const input = { provider: "google", connection: id(20), generation: active.generation, flowId,
    dpopJkt: id(5), operationId: id(80), credentialHash };
  assert.equal((await state.beginMailRefresh(input)).status, "claimed");
  for (const altered of [{ operationId: id(81) }, { flowId: id(9) }, { dpopJkt: id(6) },
    { credentialHash: id(7) }, { generation: active.generation + 1 }]) {
    assert.equal(await state.failMailRefreshScope({ ...input, ...altered }), false);
  }
  assert.equal(await state.failMailRefreshScope(input), true);
  const restarted = new TestInstallationState({ storage });
  assert.equal((await restarted.beginMailRefresh(input)).status, "insufficient_scope");
  assert.equal((await restarted.beginMailRefresh({ ...input, operationId: id(81) })).status, "insufficient_scope");
  assert.equal(await restarted.disconnect("google", id(20), active.generation), true);
  assert.equal(await restarted.failMailRefreshScope(input), false);
  assert.equal((await restarted.beginMailRefresh(input)).status, "invalid");
});

test("disconnect during an in-flight refresh prevents committing or retrieving the result", async () => {
  const storage = new MemoryObjectStorage();
  const state = await initialized(storage);
  const flowId = await prepare(state, "google", 1, 20);
  const active = await state.admit(flowId);
  const input = { provider: "google", connection: id(20), generation: active.generation, flowId,
    dpopJkt: id(5), operationId: id(80), credentialHash };
  assert.equal((await state.beginMailRefresh(input)).status, "claimed");
  assert.equal(await state.disconnect("google", id(20), active.generation), true);
  assert.equal(await state.finishMailRefresh({ ...input, nextCredentialHash, nextCredentialEnvelope: nextCredential, sealedResult }), false);
  assert.equal(await new TestInstallationState({ storage }).readMailRefresh(input), null);
});

test("cancellation and revocation prevent a pending mail result from activating", async () => {
  const cancelled = await initialized();
  const cancelledFlow = await prepare(cancelled, "google", 1, 20);
  assert.equal(await cancelled.cancelFlow(cancelledFlow), true);
  assert.equal((await cancelled.finishMailExchange(cancelledFlow, sealedResult)).ok, false);
  const revoked = await initialized();
  const revokedFlow = await prepare(revoked, "google", 1, 20);
  assert.equal(await revoked.revoke(), true);
  assert.equal((await revoked.finishMailExchange(revokedFlow, sealedResult)).ok, false);
});

test("disconnect protects a newer incarnation and preserves a shared account slot", async () => {
  const state = await initialized();
  const a = await state.admit(await prepare(state, "google", 0, 20));
  const b = await state.admit(await prepare(state, "google", 0, 21));
  for (let n = 1; n < 5; n++) assert.equal((await state.admit(await prepare(state, "google", n, n + 21))).ok, true);
  assert.equal(await state.disconnect("google", id(20), a.generation), true);
  assert.equal(await state.isActive("google", id(21), b.generation), true);
  const newFlow = await prepare(state, "google", 5, 30);
  assert.equal((await state.admit(newFlow)).reason, "limit");
  assert.equal(await state.disconnect("google", id(21), b.generation), true);
  assert.equal((await state.admit(newFlow)).ok, false); // The consumed authorization cannot be reused.
  const freshFlow = await prepare(state, "google", 5, 30);
  const first = await state.admit(freshFlow);
  assert.equal(first.ok, true);
  assert.deepEqual(await state.admit(freshFlow), first);
  const replacement = await state.admit(await prepare(state, "google", 5, 30, first.generation));
  assert.equal(await state.disconnect("google", id(30), first.generation), false);
  assert.equal(await state.isActive("google", id(30), replacement.generation), true);
});

test("disconnect cancels competing pending flows and generations never recur", async () => {
  const storage = new MemoryObjectStorage();
  const state = await initialized(storage);
  const flow1 = await prepare(state, "google", 1, 2);
  const flow2 = await prepare(state, "google", 1, 2);
  const first = await state.admit(flow1);
  assert.equal(await state.disconnect("google", id(2), first.generation), true);
  assert.equal((await state.admit(flow2)).reason, "stale");
  assert.equal((await state.admit(flow1)).reason, "stale");
  const restored = new TestInstallationState({ storage });
  const next = await restored.admit(await prepare(restored, "google", 1, 2));
  assert.notEqual(next.generation, first.generation);
  assert.equal(await restored.isActive("google", id(2), first.generation), false);
});

test("signed disconnect is idempotent and never deletes a later connection", async () => {
  const state = await initialized();
  const flow = await prepare(state, "google", 1, 20);
  const first = await state.admit(flow);
  assert.equal(await state.disconnectMail("google", id(20), first.generation, flow, id(8)), false);
  assert.equal(await state.disconnectMail("google", id(20), first.generation, flow, id(5)), true);
  const nextFlow = await prepare(state, "google", 1, 20);
  const next = await state.admit(nextFlow);
  assert.equal(await state.disconnectMail("google", id(20), first.generation, flow, id(5)), true);
  assert.equal(await state.isActive("google", id(20), next.generation), true);
  assert.equal(await state.cancelMailFlow(nextFlow, id(5)), false);
});

test("an expired retry marker cannot revoke a newer generation", async () => {
  const state = await initialized();
  const flow = await prepare(state, "google", 1, 20);
  const first = await state.admit(flow);
  const now = Date.now();
  assert.equal(await state.disconnectMail("google", id(20), first.generation, flow, id(5), now), true);
  const next = await state.admit(await prepare(state, "google", 1, 20));
  await state.sweepExpired(now + 86_400_001);
  assert.equal(await state.disconnectMail("google", id(20), first.generation, flow, id(5), now + 86_400_001), false);
  assert.equal(await state.isActive("google", id(20), next.generation), true);
});

test("mail cancellation requires the flow key and can be retried", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 20);
  assert.equal(await state.cancelMailFlow(flow, id(8)), false);
  assert.equal(await state.cancelMailFlow(flow, id(5)), true);
  assert.equal(await state.cancelMailFlow(flow, id(5)), true);
});

test("disconnect remains available when retry-marker storage is full", async () => {
  const storage = new MemoryObjectStorage();
  const state = await initialized(storage);
  const flow = await prepare(state, "google", 1, 20);
  const active = await state.admit(flow);
  const now = Date.now();
  for (let n = 0; n < 4096; n++) await storage.put(`disconnect:old:${n}`, { expiresAt: now + 60_000 + n, flowId: id(2), dpopJkt: id(5) });
  assert.equal(await state.disconnectMail("google", id(20), active.generation, flow, id(5), now), true);
  assert.equal(await state.isActive("google", id(20), active.generation), false);
  assert.equal((await storage.list({ prefix: "disconnect:" })).size, 4096);
});

test("proof replay is rejected atomically and expired entries release capacity", async () => {
  const storage = new MemoryObjectStorage();
  const state = new InstallationStateLogic({ storage });
  const expiry = Date.now() + 60000;
  assert.deepEqual((await Promise.all([state.consumeProof(id(7), expiry), state.consumeProof(id(7), expiry)])).sort(), [false, true]);
  for (let i = 0; i < 4096; i++) await storage.put(`proof:expired-${i}`, 1);
  assert.equal(await state.consumeProof(id(8), 12000, 10000), true);
});

test("installation authorization rejects another key and atomically consumes its proof", async () => {
  const state = new InstallationStateLogic({ storage: new MemoryObjectStorage() });
  const expiry = Date.now() + 60000;
  assert.equal(await state.register(id(1), id(3), expiry), true);
  assert.equal(await state.register(id(2), id(4), expiry), false);
  assert.equal(await state.authorize(id(2), id(5), expiry), false);
  assert.deepEqual((await Promise.all([state.authorize(id(1), id(6), expiry), state.authorize(id(1), id(6), expiry)])).sort(), [false, true]);
});

test("installation key rotation preserves quota state and retires the old key", async () => {
  const storage = new MemoryObjectStorage();
  const state = new InstallationStateLogic({ storage });
  const expiry = Date.now() + 60000;
  assert.equal(await state.register(id(1), id(2), expiry), true);
  await storage.put("account-history:google", [{ account: id(11), at: Date.now() }]);
  const old = n => ({ thumbprint: id(1), jti: id(n), expiresAt: expiry });
  const replacement = n => ({ thumbprint: id(3), jti: id(n), expiresAt: expiry });
  assert.equal(await state.rotate(old(4), replacement(5), id(6)), true);
  assert.equal(await state.authorize(id(1), id(7), expiry), false);
  assert.equal(await state.authorize(id(3), id(8), expiry), true);
  assert.equal(await state.rotate(old(9), replacement(10), id(6)), true); // lost response
  assert.equal(await state.rotate(old(12), { thumbprint: id(4), jti: id(13), expiresAt: expiry }, id(6)), false);
  assert.equal((await storage.get("account-history:google"))[0].account, id(11));
});

test("cancelling a pending authorization removes both records and recovers capacity", async () => {
  const state = await initialized();
  const flows = [];
  for (let n = 0; n < 100; n++) flows.push(await start(state, "google", 2));
  assert.equal(await state.createAuthFlow({ provider: "google", purpose: "mail", state: id(249), challenge: id(2), nonce: id(3),
    gatewayOrigin: "http://localhost:20229", connectionId: id(2), dpopJkt: id(5), expectedGeneration: 0 }), null);
  assert.equal(await state.cancelFlow(flows[0]), true);
  assert.equal(await state.verifyFlow(flows[0], id(1)), false);
  assert.equal((await state.admit(flows[0])).reason, "stale");
  assert.ok(await start(state, "google", 2));
});

test("revoking installation prevents an already authorized flow from admitting or refreshing", async () => {
  const state = await initialized();
  const flow = await prepare(state, "google", 1, 2);
  assert.equal(await state.revoke(), true);
  assert.equal((await state.admit(flow)).reason, "revoked");
  assert.equal(await state.isActive("google", id(2), 1), false);
});

test("browser binding rejects a copied link in another browser and callback replay", async () => {
  const state = await initialized();
  const flow = await state.createAuthFlow({ provider: "google", purpose: "login", state: id(1), challenge: id(2),
    nonce: id(3), gatewayOrigin: "http://192.168.1.10:20229" });
  const browserA = await state.browserCandidate(flow, id(10));
  assert.deepEqual(await state.browserCandidate(flow, id(10)), browserA);
  const browserB = await state.browserCandidate(flow, id(11));
  assert.equal(await state.bindBrowser(flow, browserA.nonce), true);
  assert.equal(await state.bindBrowser(flow, browserA.nonce), true);
  assert.equal(await state.bindBrowser(flow, browserB.nonce), false);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(11), id(1), { code: "victim-code" }), false);
  assert.equal(await state.recordCallback(flow, id(10), id(2), { code: "wrong-state" }), false);
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "correct-code" }), true);
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "replay" }), false);
});

test("mail cannot be admitted before the bound browser callback", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 2);
  assert.equal(await state.verifyFlow(flow, id(1)), false);
  assert.equal((await state.admit(flow)).reason, "stale");
});

test("provider denial cannot become a verified or admitted mail account", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 2);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), states.get(flow), { error: "access_denied" }), true);
  assert.equal(await state.verifyFlow(flow, id(1)), false);
  assert.equal((await state.admit(flow)).reason, "stale");
});

test("provider exchange is claimed once and unknown outcomes never restart automatically", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 2);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), states.get(flow), { code: "one-use-code" }), true);
  assert.equal(await state.beginExchange(flow, verifier, id(9)), null);
  const claims = await Promise.all([state.beginExchange(flow, verifier, id(5)), state.beginExchange(flow, verifier, id(5))]);
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(await state.failExchange(flow), true);
  assert.equal(await state.beginExchange(flow, verifier, id(5)), null);
  assert.equal(await state.verifyFlow(flow, id(1)), false);
});

test("mail identity cannot be verified after the provider exchange lease expires", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 2);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), states.get(flow), { code: "one-use-code" }), true);
  const startedAt = Date.now();
  assert.ok(await state.beginExchange(flow, verifier, id(5), startedAt));
  assert.equal(await state.verifyFlow(flow, id(1), startedAt + 60_000), false);
  assert.equal((await state.admit(flow, startedAt + 60_001)).ok, false);
});

test("an identity verified before the deadline cannot be admitted after it", async () => {
  const state = await initialized();
  const flow = await start(state, "google", 2);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), states.get(flow), { code: "one-use-code" }), true);
  const startedAt = Date.now();
  assert.ok(await state.beginExchange(flow, verifier, id(5), startedAt));
  assert.equal(await state.verifyFlow(flow, id(1), startedAt + 59_999), true);
  assert.equal((await state.admit(flow, startedAt + 60_000)).ok, false);
});

test("social exchange result is released only for the original verifier and current installation", async () => {
  const state = await initialized();
  const flow = await state.createAuthFlow({ provider: "google", purpose: "login", state: id(1), challenge,
    nonce: id(3), gatewayOrigin: "http://localhost:20229" });
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "one-use-code" }), true);
  assert.ok(await state.beginExchange(flow, verifier, null));
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "one-use-code" }), true);
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "different" }), false);
  assert.equal(await state.beginExchange(flow, verifier, null), null);
  assert.equal(await state.finishSocialExchange(flow, "sealed." + "x".repeat(40)), true);
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "one-use-code" }), true);
  assert.equal(await state.readSocialExchange(flow, id(4)), null);
  assert.equal(await state.readSocialExchange(flow, verifier), "sealed." + "x".repeat(40));
  assert.equal(await state.revoke(), true);
  assert.equal(await state.readSocialExchange(flow, verifier), null);
});

test("a lost provider exchange becomes terminal and a late result cannot revive it", async () => {
  const state = await initialized();
  const flow = await state.createAuthFlow({ provider: "google", purpose: "login", state: id(1), challenge,
    nonce: id(3), gatewayOrigin: "http://localhost:20229" });
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "one-use-code" }), true);
  const startedAt = Date.now();
  assert.ok(await state.beginExchange(flow, verifier, null, startedAt));
  assert.equal(await state.socialExchangeStatus(flow, verifier, startedAt + 29_999), "pending");
  assert.equal(await state.socialExchangeStatus(flow, verifier, startedAt + 30_000), "failed");
  assert.equal(await state.beginExchange(flow, verifier, null, startedAt + 30_001), null);
  assert.equal(await state.finishSocialExchange(flow, "sealed." + "x".repeat(40), startedAt + 30_001), false);
  assert.equal(await state.readSocialExchange(flow, verifier, startedAt + 30_001), null);
});

test("social status distinguishes pending and provider denial without disclosing to wrong verifier", async () => {
  const state = await initialized();
  const flow = await state.createAuthFlow({ provider: "google", purpose: "login", state: id(1), challenge,
    nonce: id(3), gatewayOrigin: "http://localhost:20229" });
  assert.equal(await state.socialExchangeStatus(flow, verifier), "pending");
  assert.equal(await state.socialExchangeStatus(flow, id(9)), "invalid");
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.ok(await state.startProvider(flow, id(10)));
  assert.equal(await state.recordCallback(flow, id(10), id(1), { error: "access_denied" }), true);
  assert.equal(await state.socialExchangeStatus(flow, verifier), "failed");
});

test("flow start retries return the existing flow only for identical parameters", async () => {
  const state = await initialized();
  const input = { provider: "google", purpose: "login", state: id(1), challenge: id(2), nonce: id(3), gatewayOrigin: "https://appliance.example" };
  const first = await state.createAuthFlow(input);
  assert.ok(first);
  assert.equal(await state.createAuthFlow(input), first);
  assert.equal(await state.createAuthFlow({ ...input, gatewayOrigin: "https://attacker.example" }), null);
});

test("disconnect cancels linked authorization and admission state", async () => {
  const state = await initialized();
  const initial = await state.admit(await prepare(state, "google", 1, 2));
  const flow = await start(state, "google", 2, initial.generation);
  const browser = await state.browserCandidate(flow, id(10));
  assert.equal(await state.bindBrowser(flow, browser.nonce), true);
  assert.equal(await state.disconnect("google", id(2), initial.generation), true);
  assert.equal(await state.recordCallback(flow, id(10), id(1), { code: "late" }), false);
  assert.equal(await state.verifyFlow(flow, id(1)), false);
  assert.equal((await state.admit(flow)).reason, "stale");
});
