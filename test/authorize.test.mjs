import assert from "node:assert/strict";
import test from "node:test";
import { onRequestPost as confirm } from "../functions/start/confirm.js";
import { onRequestGet as authorize } from "../functions/authorize.js";

const secret = "0123456789abcdef0123456789abcdef";
const challenge = "a".repeat(43);
const state = "b".repeat(43);
const nonce = "c".repeat(43);
const authOrigin = "https://auth.example.test";

for (const [connector, clientVariable, clientId, additional, expectedHost] of [
  ["kautuka-google-mail", "GOOGLE_CLIENT_ID", "google-client", {}, "accounts.google.com"],
  ["kautuka-m365-mail", "MICROSOFT_CLIENT_ID", "microsoft-client", {}, "login.microsoftonline.com"],
  ["kautuka-login-google", "GOOGLE_LOGIN_CLIENT_ID", "google-login", { nonce }, "accounts.google.com"],
  ["kautuka-login-microsoft", "MICROSOFT_LOGIN_CLIENT_ID", "microsoft-login", { nonce, microsoftAccountType: "organizations" }, "login.microsoftonline.com"],
]) {
  test(`${connector} requires confirmation and redirects using the signed ticket`, async () => {
    const data = {
      returnUrl: `https://appliance.example.test/${connector.startsWith("kautuka-login-") ? "login/callback" : "connectors"}`,
      connector,
      state,
      challenge,
      ...additional,
    };
    const before = await authorize({
      env: { AUTH_TICKET_HMAC_KEY: secret, [clientVariable]: clientId },
      request: new Request(`${authOrigin}/authorize?connector=${connector}&state=${state}&challenge=${challenge}`),
    });
    assert.equal(before.status, 400);

    const ticketResponse = await confirm({
      env: { AUTH_TICKET_HMAC_KEY: secret },
      request: new Request(`${authOrigin}/start/confirm`, {
        method: "POST",
        headers: { origin: authOrigin, "content-type": "application/json", "sec-fetch-site": "same-origin" },
        body: JSON.stringify(data),
      }),
    });
    assert.equal(ticketResponse.status, 200);
    assert.equal(ticketResponse.headers.get("cache-control"), "no-store");
    const { ticket } = await ticketResponse.json();

    const response = await authorize({
      env: { AUTH_TICKET_HMAC_KEY: secret, [clientVariable]: clientId },
      request: new Request(`${authOrigin}/authorize?ticket=${encodeURIComponent(ticket)}`),
    });
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get("location"));
    assert.equal(location.hostname, expectedHost);
    assert.equal(location.searchParams.get("client_id"), clientId);
    assert.equal(location.searchParams.get("redirect_uri"), `${authOrigin}/callback`);
    assert.equal(location.searchParams.get("state"), `k1.${ticket}`);
    assert.equal(location.searchParams.get("code_challenge"), challenge);
    if (connector.startsWith("kautuka-login-")) assert.equal(location.searchParams.get("nonce"), nonce);
    if (connector === "kautuka-login-microsoft") assert.match(location.pathname, /^\/organizations\//);
  });
}

test("confirmation rejects a cross-origin request and a malformed return origin", async () => {
  const body = JSON.stringify({ returnUrl: "https://appliance.test/login/callback", connector: "kautuka-login-google", state, challenge, nonce });
  const crossOrigin = await confirm({
    env: { AUTH_TICKET_HMAC_KEY: secret },
    request: new Request(`${authOrigin}/start/confirm`, { method: "POST", headers: { origin: "https://attacker.test", "content-type": "application/json" }, body }),
  });
  assert.equal(crossOrigin.status, 400);
  const invalid = await confirm({
    env: { AUTH_TICKET_HMAC_KEY: secret },
    request: new Request(`${authOrigin}/start/confirm`, { method: "POST", headers: { origin: authOrigin, "content-type": "application/json" }, body: JSON.stringify({ returnUrl: "http://example.test/login/callback", connector: "kautuka-login-google", state, challenge, nonce }) }),
  });
  assert.equal(invalid.status, 400);
});

test("authorize rejects a ticket with a different audience or an altered signature", async () => {
  const ticketResponse = await confirm({
    env: { AUTH_TICKET_HMAC_KEY: secret },
    request: new Request(`${authOrigin}/start/confirm`, {
      method: "POST",
      headers: { origin: authOrigin, "content-type": "application/json" },
      body: JSON.stringify({ returnUrl: "https://appliance.test/connectors", connector: "kautuka-google-mail", state, challenge }),
    }),
  });
  const { ticket } = await ticketResponse.json();
  const env = { AUTH_TICKET_HMAC_KEY: secret, GOOGLE_CLIENT_ID: "client" };
  for (const candidate of [ticket.slice(0, -1) + "x", "bad.ticket"]) {
    const response = await authorize({ env, request: new Request(`${authOrigin}/authorize?ticket=${encodeURIComponent(candidate)}`) });
    assert.equal(response.status, 400);
  }
  const wrongAudience = await authorize({ env, request: new Request("https://other.example.test/authorize?ticket=" + encodeURIComponent(ticket)) });
  assert.equal(wrongAudience.status, 400);
});
