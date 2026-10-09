import assert from "node:assert/strict";
import test from "node:test";

import { isAllowedReturn } from "../public/return-path.js";

test("mailbox sign-in can return only to the connectors page", () => {
  assert.equal(isAllowedReturn("https://appliance.example/connectors", "kautuka-google-mail"), true);
  assert.equal(isAllowedReturn("https://appliance.example/login/callback", "kautuka-google-mail"), false);
  assert.equal(isAllowedReturn("http://192.168.1.20/connectors", "kautuka-m365-mail"), true);
});

test("appliance login can return only to the login callback", () => {
  assert.equal(isAllowedReturn("https://appliance.example/login/callback", "kautuka-login-google"), true);
  assert.equal(isAllowedReturn("http://127.0.0.1:20229/login/callback", "kautuka-login-microsoft"), true);
  assert.equal(isAllowedReturn("https://appliance.example/connectors", "kautuka-login-microsoft"), false);
  assert.equal(isAllowedReturn("https://appliance.example/login/callback?next=1", "kautuka-login-google"), false);
});
