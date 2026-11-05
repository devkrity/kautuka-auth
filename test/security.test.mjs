import assert from "node:assert/strict";
import test from "node:test";
import { sealMailFlowResult, openMailFlowResult } from "../functions/_shared/token-state.js";
import { onRequest as middleware } from "../functions/_middleware.js";

const aes = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const keyringEnv = { REFRESH_TOKEN_KEYS: JSON.stringify({ old: aes, active: aes }), REFRESH_TOKEN_ACTIVE_KID: "active" };
test("legacy hosted authorization and token paths are retired before handlers run", async () => {
  const paths = ["/authorize", "/start/confirm", "/callback/validate", "/login/google/token", "/login/microsoft/token",
    "/google-mail/token", "/microsoft-mail/token", "/google-mail/keys/test", "/microsoft-mail/keys/test", "/google-mail%2Ftoken"];
  for (const path of paths) {
    let invoked = false;
    const response = await middleware({ request: new Request(`https://auth.example.test${path}`), next: async () => { invoked = true; return new Response("old handler"); } });
    assert.equal(response.status, 410, path);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(invoked, false, path);
  }
  const allowed = await middleware({ request: new Request("https://auth.example.test/installation/mail-refresh"), next: async () => new Response("new handler") });
  assert.equal(await allowed.text(), "new handler");
});

test("sealed mail results cannot be opened by another installation, flow or connection key", async () => {
  const installation = "A".repeat(43), flow = "B".repeat(43), key = "C".repeat(43), other = "D".repeat(43);
  const result = JSON.stringify({ access_token: "access", refresh_token: "wrapped" });
  const envelope = await sealMailFlowResult(keyringEnv, installation, flow, key, result);
  assert.equal(await openMailFlowResult(keyringEnv, installation, flow, key, envelope), result);
  assert.equal(await openMailFlowResult(keyringEnv, other, flow, key, envelope), null);
  assert.equal(await openMailFlowResult(keyringEnv, installation, other, key, envelope), null);
  assert.equal(await openMailFlowResult(keyringEnv, installation, flow, other, envelope), null);
  assert.equal(await openMailFlowResult(keyringEnv, installation, flow, key, envelope + "x"), null);
});
