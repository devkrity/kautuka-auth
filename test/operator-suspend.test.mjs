import { test } from "node:test";
import assert from "node:assert/strict";
import { onRequestPost } from "../functions/operator/installations/suspend.js";
import { InstallationStateLogic } from "../installation-state/src/state.js";
import { MemoryObjectStorage } from "./helpers/dpop-state.mjs";

const id = n => Buffer.alloc(32, n).toString("base64url");
test("operator suspension requires independent authentication and leaves a permanent tombstone", async () => {
  const state = new InstallationStateLogic({ storage: new MemoryObjectStorage() });
  const now = Date.now();
  assert.equal(await state.register(id(1), id(2), now + 60_000), true);
  const secret = id(3), body = JSON.stringify({ id: id(4), operationId: id(5), reason: "key_compromised" });
  const env = { OPERATOR_SUSPEND_SECRET: secret, OPERATOR_SUSPEND_CREDENTIAL_ID: "test-cli", BROKER_ORIGIN: "https://broker.example",
    INSTALLATION_CONTROL_LIMIT: { async limit() { return { success: true }; } },
    INSTALLATION_STATE: { idFromName(value) { return value; }, get() { return { async fetch(url, init) {
      const input = JSON.parse(init.body);
      return Response.json({ status: await state.operatorSuspend(input.operationId, input.reason, input.operatorId) });
    } }; } } };
  const invoke = (token, origin, target = "https://broker.example/operator/installations/suspend", configuration = env) => onRequestPost({
    request: new Request(target, { method: "POST", body, headers: { "content-type": "application/json", "CF-Connecting-IP": "192.0.2.1",
      ...(token ? { authorization: `Bearer ${token}` } : {}), ...(origin ? { origin } : {}) } }), env: configuration });
  assert.equal((await invoke(null)).status, 403);
  assert.equal((await invoke(id(6))).status, 403);
  assert.equal((await invoke(secret, "https://attacker.example")).status, 403);
  assert.equal((await invoke(secret, null, "https://alternate.example/operator/installations/suspend")).status, 403);
  assert.equal((await invoke(secret, null, undefined, { ...env, OPERATOR_SUSPEND_SECRET: undefined })).status, 503);
  assert.equal((await (await invoke(secret)).json()).status, "suspended");
  assert.equal((await (await invoke(secret)).json()).status, "already_suspended");
  assert.equal(await state.register(id(1), id(7), now + 60_000), false);
  assert.equal(await state.authorize(id(1), id(8), now + 60_000), false);
});
