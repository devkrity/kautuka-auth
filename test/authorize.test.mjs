import assert from "node:assert/strict";
import test from "node:test";

import { onRequestGet } from "../functions/authorize.js";

const challenge = "a".repeat(43);
const state = "b".repeat(43);

test("the auth host inserts the Google client id", async () => {
  const response = await onRequestGet({
    env: { GOOGLE_CLIENT_ID: "123456789012-abcdef.apps.googleusercontent.com" },
    request: new Request(
      `https://auth.example.test/authorize?connector=kautuka-google-mail&state=${state}&challenge=${challenge}`,
    ),
  });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get("location"));
  assert.equal(location.hostname, "accounts.google.com");
  assert.equal(location.searchParams.get("client_id"), "123456789012-abcdef.apps.googleusercontent.com");
  assert.equal(location.searchParams.get("redirect_uri"), "https://auth.example.test/callback");
  assert.equal(location.searchParams.get("code_challenge"), challenge);
  assert.equal(location.searchParams.get("access_type"), "offline");
});

test("the auth host inserts the Microsoft client id", async () => {
  const response = await onRequestGet({
    env: { MICROSOFT_CLIENT_ID: "11111111-1111-1111-1111-111111111111" },
    request: new Request(
      `https://auth.example.test/authorize?connector=kautuka-m365-mail&state=${state}&challenge=${challenge}`,
    ),
  });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get("location"));
  assert.equal(location.hostname, "login.microsoftonline.com");
  assert.equal(location.searchParams.get("client_id"), "11111111-1111-1111-1111-111111111111");
  assert.equal(location.searchParams.get("redirect_uri"), "https://auth.example.test/callback");
});

test("an unknown connector is rejected", async () => {
  const response = await onRequestGet({
    env: { GOOGLE_CLIENT_ID: "client" },
    request: new Request(
      `https://auth.example.test/authorize?connector=other-mail&state=${state}&challenge=${challenge}`,
    ),
  });
  assert.equal(response.status, 400);
});
