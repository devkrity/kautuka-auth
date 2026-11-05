import assert from "node:assert/strict";
import test from "node:test";

import { isAllowedGatewayOrigin, isAllowedReturn } from "../public/return-path.js";

test("gateway origin allows secure or local canonical origins only", () => {
  for (const origin of ["https://public.example", "http://localhost:20229", "http://192.168.1.20", "http://172.16.0.1", "http://172.31.255.255", "http://kautuka.local:5000", "http://[::1]:20229", "http://[fd00::1]"]) {
    assert.equal(isAllowedGatewayOrigin(origin), true, origin);
  }
  for (const origin of ["http://public.example", "http://8.8.8.8", "http://172.15.255.255", "http://172.32.0.1", "http://2130706433", "http://0x7f000001", "http://127.0.0.1:80", "http://gateway.office.local", "http://public.example.", "https://user@public.example", "https://public.example/path", "https://public.example?x=1", "https://public.example#fragment", "http://[::2]", "http://xn--bcher-kva.local", "http://localhost\\@public.example"]) {
    assert.equal(isAllowedGatewayOrigin(origin), false, origin);
  }
});

test("mailbox sign-in can return only to the connectors page", () => {
  assert.equal(isAllowedReturn("https://appliance.example/connectors", "kautuka-google-mail"), true);
  assert.equal(isAllowedReturn("https://appliance.example/login/callback", "kautuka-google-mail"), false);
  assert.equal(isAllowedReturn("http://192.168.1.20/connectors", "kautuka-m365-mail"), true);
  assert.equal(isAllowedReturn("http://kautuka.local:5000/connectors", "kautuka-m365-mail"), true);
  assert.equal(isAllowedReturn("http://gateway.office.local/connectors", "kautuka-m365-mail"), false);
});

test("appliance login can return only to the login callback", () => {
  assert.equal(isAllowedReturn("https://appliance.example/login/callback", "kautuka-login-google"), true);
  assert.equal(isAllowedReturn("http://127.0.0.1:20229/login/callback", "kautuka-login-microsoft"), true);
  assert.equal(isAllowedReturn("http://kautuka.local:5000/login/callback", "kautuka-login-microsoft"), true);
  assert.equal(isAllowedReturn("http://-invalid.local/login/callback", "kautuka-login-microsoft"), false);
  assert.equal(isAllowedReturn("http://invalid-.local/login/callback", "kautuka-login-microsoft"), false);
  assert.equal(isAllowedReturn("https://appliance.example/connectors", "kautuka-login-microsoft"), false);
  assert.equal(isAllowedReturn("https://appliance.example/login/callback?next=1", "kautuka-login-google"), false);
});
