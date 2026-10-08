import assert from "node:assert/strict";
import test from "node:test";

import { onRequestPost } from "../../functions/microsoft-mail/token.js";

test("a token request that already carries a client id is rejected", async () => {
  const response = await onRequestPost({
    env: { MICROSOFT_CLIENT_ID: "11111111-1111-1111-1111-111111111111" },
    request: new Request("https://auth.example.test/microsoft-mail/token", {
      method: "POST",
      body: "grant_type=authorization_code&client_id=caller&code=c&code_verifier=v&redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback",
    }),
  });
  assert.equal(response.status, 400);
});

test("the auth host adds the Microsoft client id and keeps the code verifier", async () => {
  const previous = globalThis.fetch;
  let forwarded = "";
  globalThis.fetch = async (_url, init) => {
    forwarded = init.body.toString();
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const response = await onRequestPost({
      env: { MICROSOFT_CLIENT_ID: "11111111-1111-1111-1111-111111111111" },
      request: new Request("https://auth.example.test/microsoft-mail/token", {
        method: "POST",
        body: "grant_type=authorization_code&code=auth-code&code_verifier=verifier-secret&redirect_uri=https://auth.example.test/callback",
      }),
    });
    assert.equal(response.status, 200);
    assert.match(forwarded, /client_id=11111111-1111-1111-1111-111111111111/);
    assert.match(forwarded, /code_verifier=verifier-secret/);
    assert.doesNotMatch(forwarded, /client_secret/);
  } finally {
    globalThis.fetch = previous;
  }
});
