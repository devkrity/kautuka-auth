import assert from "node:assert/strict";
import test from "node:test";
import worker from "../dist/worker/index.js";

test("built router blocks retired hosted flows before their handlers", async () => {
  const env = { ASSETS: { fetch: async () => new Response("asset fallback", { status: 404 }) } };
  const context = { waitUntil() {}, passThroughOnException() {} };
  const cases = [
    ["/authorize", 410], ["/AUTHORIZE/", 410], ["/google-mail/token", 410], ["/microsoft-mail/token", 410],
    ["/google-mail/token//", 410], ["/google-mail%2ftoken", 410], ["/google-mail/keys/test", 410],
    ["/microsoft-mail/keys/test", 410], ["/start/confirm", 410], ["/callback/validate", 410],
    ["/login/google/token", 410], ["/login/microsoft/token", 410], ["/google-mail/token.json", 404],
    ["//google-mail/token", 404], ["/google-mail//token", 404], ["/login/exchange", 404],
    ["/__local_test_object", 404], ["/__test_refresh_started", 404], ["/__test_refresh_release", 404], ["/__test_refresh_rearm", 404], ["/__test_partial_refresh", 404], ["/__test_provider_stats", 404],
    ["/__test_ack_arm", 404], ["/__test_ack_status", 404], ["/__test_ack_release", 404],
  ];
  for (const [path, expected] of cases) {
    const response = await worker.fetch(new Request(`https://auth.kautuka.io${path}`, { method: "POST" }), env, context);
    assert.equal(response.status, expected, path);
  }
  for (const [path, method] of [["/authorize", "GET"], ["/google-mail/keys/test", "DELETE"], ["/microsoft-mail/keys/test", "DELETE"]]) {
    const response = await worker.fetch(new Request(`https://auth.kautuka.io${path}`, { method }), env, context);
    assert.equal(response.status, 410, `${method} ${path}`);
  }
});
