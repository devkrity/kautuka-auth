import assert from "node:assert/strict";
import test from "node:test";
import { issueTicket, readTicket, validReturn } from "../functions/_shared/ticket.js";
import { isAllowedReturn } from "../public/return-path.js";
import { isKeyringReady, wrapRefreshToken, unwrapRefreshToken } from "../functions/_shared/token-state.js";

const now = Date.now();
const hmac = "0123456789abcdef0123456789abcdef";
const aes = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const keyringEnv = { REFRESH_TOKEN_KEYS: JSON.stringify({ old: aes, active: aes }), REFRESH_TOKEN_ACTIVE_KID: "active" };
const claims = {
  aud: "https://auth.example.test",
  returnUrl: "https://appliance.example.test/login/callback",
  connector: "kautuka-login-google",
  state: "s".repeat(43),
  challenge: "c".repeat(43),
  nonce: "n".repeat(43),
  microsoftAccountType: "",
};

test("broker tickets are signed, audience-bound, typed, and expire within five minutes", async () => {
  const ticket = await issueTicket({ AUTH_TICKET_HMAC_KEY: hmac }, claims);
  assert.ok(await readTicket({ AUTH_TICKET_HMAC_KEY: hmac }, ticket, claims.aud));
  assert.equal(await readTicket({ AUTH_TICKET_HMAC_KEY: hmac }, ticket, "https://other.example.test"), null);
  assert.equal(await readTicket({ AUTH_TICKET_HMAC_KEY: `${hmac}x` }, ticket, claims.aud), null);
  assert.equal(await readTicket({ AUTH_TICKET_HMAC_KEY: hmac }, `${ticket.slice(0, -1)}x`, claims.aud), null);
  const [body] = ticket.split(".");
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  assert.equal(payload.exp - payload.iat, 300);
  assert.ok(payload.iat >= Math.floor(now / 1000));

  const actualNow = Date.now;
  let expiredTicket;
  try {
    Date.now = () => 1_600_000_000_000;
    expiredTicket = await issueTicket({ AUTH_TICKET_HMAC_KEY: hmac }, claims);
  } finally {
    Date.now = actualNow;
  }
  assert.equal(await readTicket({ AUTH_TICKET_HMAC_KEY: hmac }, expiredTicket, claims.aud), null);
});

test("ticket returns permit HTTPS and private HTTP appliance callbacks only", () => {
  assert.equal(validReturn(claims.returnUrl, claims.connector), true);
  assert.equal(isAllowedReturn(claims.returnUrl, claims.connector), true);
  assert.equal(validReturn("http://10.1.2.3:8888/login/callback", claims.connector), true);
  assert.equal(validReturn("http://[fd00::1]:9000/login/callback", claims.connector), true);
  for (const value of [
    "http://public.example.test/login/callback",
    "http://printer.local/login/callback",
    "http://169.254.169.254/login/callback",
    "http://[fe8::1]/login/callback",
    "http://user@127.0.0.1/login/callback",
    "http://127.0.0.1./login/callback",
    "http://127.0.0.1/%2fadmin",
    "https://xn--not-ascii.test/login/callback",
  ]) {
    assert.equal(validReturn(value, claims.connector), false, value);
    assert.equal(isAllowedReturn(value, claims.connector), false, value);
  }
});

test("refresh envelopes are authenticated, provider and thumbprint bound, and raw values fail", async () => {
  const jkt = "J".repeat(43);
  const envelope = await wrapRefreshToken(keyringEnv, "google-mail", jkt, "refresh secret");
  assert.match(envelope, /^krt1\.active\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  assert.equal(await unwrapRefreshToken(keyringEnv, "google-mail", jkt, envelope), "refresh secret");
  assert.equal(await unwrapRefreshToken(keyringEnv, "microsoft-mail", jkt, envelope), null);
  assert.equal(await unwrapRefreshToken(keyringEnv, "google-mail", "K".repeat(43), envelope), null);
  assert.equal(await unwrapRefreshToken(keyringEnv, "google-mail", jkt, `${envelope}x`), null);
  assert.equal(await unwrapRefreshToken(keyringEnv, "google-mail", jkt, "refresh secret"), null);
  assert.equal(isKeyringReady(keyringEnv), true);
  assert.equal(isKeyringReady({ REFRESH_TOKEN_KEYS: "invalid", REFRESH_TOKEN_ACTIVE_KID: "active" }), false);
  assert.equal(await unwrapRefreshToken({ ...keyringEnv, REFRESH_TOKEN_KEYS: "{}" }, "google-mail", jkt, envelope), null);
});

test("envelopes decrypt with a retained old key after rotation", async () => {
  const jkt = "K".repeat(43);
  const oldKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const newKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const before = { REFRESH_TOKEN_KEYS: JSON.stringify({ k1: oldKey }), REFRESH_TOKEN_ACTIVE_KID: "k1" };
  const envelope = await wrapRefreshToken(before, "microsoft-mail", jkt, "microsoft refresh");
  const after = { REFRESH_TOKEN_KEYS: JSON.stringify({ k1: oldKey, k2: newKey }), REFRESH_TOKEN_ACTIVE_KID: "k2" };
  assert.equal(await unwrapRefreshToken(after, "microsoft-mail", jkt, envelope), "microsoft refresh");
  assert.match(await wrapRefreshToken(after, "microsoft-mail", jkt, "rotated"), /^krt1\.k2\./);
});


