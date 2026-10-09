import assert from "node:assert/strict";
import test from "node:test";

import { onRequestPost as google } from "../../functions/login/google/token.js";
import { onRequestPost as microsoft } from "../../functions/login/microsoft/token.js";

test("the Google login exchange returns only the identity token", async () => {
  const seen = await capture(google, {
    GOOGLE_LOGIN_CLIENT_ID: "login-client",
    GOOGLE_LOGIN_CLIENT_SECRET: "login-secret",
  }, "https://auth.example.test/login/google/token");
  assert.equal(seen.status, 200);
  assert.deepEqual(seen.body, { id_token: "header.payload.signature" });
  assert.equal(seen.outbound.get("client_id"), "login-client");
  assert.equal(seen.outbound.get("client_secret"), "login-secret");
  assert.equal(seen.outbound.get("code_verifier"), "verifier");
  assert.equal(seen.url, "https://oauth2.googleapis.com/token");
});

test("the Microsoft login exchange uses the Microsoft token endpoint", async () => {
  const seen = await capture(microsoft, {
    MICROSOFT_LOGIN_CLIENT_ID: "22222222-2222-2222-2222-222222222222",
    MICROSOFT_LOGIN_CLIENT_SECRET: "ms-secret",
  }, "https://auth.example.test/login/microsoft/token");
  assert.equal(seen.status, 200);
  assert.equal(seen.url, "https://login.microsoftonline.com/common/oauth2/v2.0/token");
});

test("a caller-supplied client secret is rejected", async () => {
  const response = await google({
    env: { GOOGLE_LOGIN_CLIENT_ID: "id", GOOGLE_LOGIN_CLIENT_SECRET: "secret" },
    request: new Request("https://auth.example.test/login/google/token", {
      method: "POST",
      body: "grant_type=authorization_code&client_secret=stolen&code=code&code_verifier=verifier&redirect_uri=https://auth.example.test/callback",
    }),
  });
  assert.equal(response.status, 400);
});

test("an oversized login exchange is rejected", async () => {
  const response = await google({
    env: { GOOGLE_LOGIN_CLIENT_ID: "id", GOOGLE_LOGIN_CLIENT_SECRET: "secret" },
    request: new Request("https://auth.example.test/login/google/token", {
      method: "POST",
      body: "a".repeat(8001),
    }),
  });
  assert.equal(response.status, 400);
});

test("missing login secrets are not configured", async () => {
  const response = await google({
    env: {},
    request: new Request("https://auth.example.test/login/google/token", { method: "POST", body: "" }),
  });
  assert.equal(response.status, 503);
});

async function capture(handler, env, requestUrl) {
  const previous = globalThis.fetch;
  let outbound = new URLSearchParams();
  let url = "";
  globalThis.fetch = async (target, init) => {
    url = String(target);
    outbound = new URLSearchParams(init.body);
    return new Response(JSON.stringify({
      id_token: "header.payload.signature",
      access_token: "access",
      refresh_token: "refresh",
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const response = await handler({
      env,
      request: new Request(requestUrl, {
        method: "POST",
        body: "grant_type=authorization_code&code=code&code_verifier=verifier&redirect_uri=https://auth.example.test/callback",
      }),
    });
    return { status: response.status, body: await response.json(), outbound, url };
  } finally {
    globalThis.fetch = previous;
  }
}
