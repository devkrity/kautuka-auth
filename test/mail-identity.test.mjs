import { test } from "node:test";
import assert from "node:assert/strict";
import { isMailIdentityConfigured, resolveMailAccount } from "../functions/_shared/mail-identity.js";

const id = Buffer.alloc(32, 1).toString("base64url");
const otherId = Buffer.alloc(32, 2).toString("base64url");
const env = { MAIL_ACCOUNT_PSEUDONYM_KEY: Buffer.alloc(32, 3).toString("base64") };

test("identity key readiness rejects missing and non-canonical secrets", () => {
  assert.equal(isMailIdentityConfigured(env), true);
  assert.equal(isMailIdentityConfigured({}), false);
  assert.equal(isMailIdentityConfigured({ MAIL_ACCOUNT_PSEUDONYM_KEY: "A".repeat(42) + "B=" }), false);
});

test("mail identity comes from the provider using the granted token and is installation-scoped", async () => {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push([url, options]);
    return Response.json(url.includes("googleapis") ? { sub: "google-user" } : { id: "microsoft-user" });
  };
  try {
    const google = await resolveMailAccount(env, "google", id, "access-token");
    assert.match(google, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(await resolveMailAccount(env, "google", id, "access-token"), google);
    assert.notEqual(await resolveMailAccount(env, "google", otherId, "access-token"), google);
    assert.notEqual(await resolveMailAccount(env, "microsoft", id, "access-token"), google);
    assert.equal(calls[0][0], "https://openidconnect.googleapis.com/v1/userinfo");
    assert.equal(calls[3][0], "https://graph.microsoft.com/v1.0/me?$select=id");
    assert.equal(calls[0][1].headers.authorization, "Bearer access-token");
    assert.equal(calls[0][1].redirect, "manual");
  } finally { globalThis.fetch = original; }
});

test("mail identity fails closed on bad configuration, provider failure, oversized or malformed responses", async () => {
  const original = globalThis.fetch;
  try {
    let calls = 0;
    globalThis.fetch = async () => { calls++; return new Response(null, { status: 401 }); };
    assert.equal(await resolveMailAccount({}, "google", id, "token"), null);
    assert.equal(calls, 0);
    assert.equal(await resolveMailAccount(env, "google", id, "token"), null);
    globalThis.fetch = async (_url, options) => { assert.equal(options.redirect, "manual"); return new Response(null, { status: 302, headers: { location: "https://attacker.example/" } }); };
    assert.equal(await resolveMailAccount(env, "google", id, "token"), null);
    globalThis.fetch = async () => new Response("x".repeat(16385));
    assert.equal(await resolveMailAccount(env, "google", id, "token"), null);
    globalThis.fetch = async () => Response.json({ sub: "\ninvalid" });
    assert.equal(await resolveMailAccount(env, "google", id, "token"), null);
    globalThis.fetch = async () => { throw new Error("offline"); };
    assert.equal(await resolveMailAccount(env, "microsoft", id, "token"), null);
  } finally { globalThis.fetch = original; }
});
