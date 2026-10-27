import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { issueTicket } from "../../functions/_shared/ticket.js";
import { onRequestPost as google } from "../../functions/login/google/token.js";
import { onRequestPost as microsoft } from "../../functions/login/microsoft/token.js";

const secret = "test-secret";
const authOrigin = "https://auth.example.test";
const applianceOrigin = "https://appliance.example.test";
const verifier = "verifier-01234567890123456789012345678901234567890";
const challenge = createHash("sha256").update(verifier).digest("base64url");
const clientState = "s".repeat(43);
const nonce = "n".repeat(43);

async function ticket(connector) {
  return issueTicket({ AUTH_TICKET_HMAC_KEY: secret }, {
    aud: authOrigin,
    returnUrl: `${applianceOrigin}/login/callback`,
    connector,
    state: clientState,
    challenge,
    nonce,
    microsoftAccountType: "",
  });
}

for (const [label, handler, connector, env, expectedEndpoint] of [
  ["Google", google, "kautuka-login-google", { GOOGLE_LOGIN_CLIENT_ID: "google-id", GOOGLE_LOGIN_CLIENT_SECRET: "google-secret" }, "https://oauth2.googleapis.com/token"],
  ["Microsoft", microsoft, "kautuka-login-microsoft", { MICROSOFT_LOGIN_CLIENT_ID: "microsoft-id", MICROSOFT_LOGIN_CLIENT_SECRET: "microsoft-secret" }, "https://login.microsoftonline.com/common/oauth2/v2.0/token"],
]) {
  test(`${label} login exchange inserts host credentials and returns only id_token`, async () => {
    const brokerTicket = await ticket(connector);
    const previousFetch = globalThis.fetch;
    let outbound;
    let endpoint;
    globalThis.fetch = async (target, init) => {
      endpoint = String(target);
      outbound = new URLSearchParams(init.body);
      return new Response(JSON.stringify({ id_token: "header.payload.signature", access_token: "hidden-access", refresh_token: "hidden-refresh" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    try {
      const response = await handler({
        env: { ...env, AUTH_TICKET_HMAC_KEY: secret },
        request: new Request(`${authOrigin}/login/${label.toLowerCase()}/token`, {
          method: "POST",
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code: "provider-code",
            code_verifier: verifier,
            redirect_uri: `${authOrigin}/callback`,
            broker_ticket: brokerTicket,
            return_origin: applianceOrigin,
          }),
        }),
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { id_token: "header.payload.signature" });
      assert.equal(endpoint, expectedEndpoint);
      assert.equal(outbound.get("client_id"), env[label === "Google" ? "GOOGLE_LOGIN_CLIENT_ID" : "MICROSOFT_LOGIN_CLIENT_ID"]);
      assert.equal(outbound.get("client_secret"), env[label === "Google" ? "GOOGLE_LOGIN_CLIENT_SECRET" : "MICROSOFT_LOGIN_CLIENT_SECRET"]);
      assert.equal(outbound.get("code_verifier"), verifier);
      assert.equal(outbound.get("redirect_uri"), `${authOrigin}/callback`);
      assert.equal(outbound.has("broker_ticket"), false);
      assert.equal(outbound.has("return_origin"), false);
      assert.equal(response.headers.get("cache-control"), "no-store");
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
}

test("login exchange rejects caller credentials, wrong PKCE, ticket, origin and oversized body before upstream", async () => {
  const brokerTicket = await ticket("kautuka-login-google");
  const base = new URLSearchParams({ grant_type: "authorization_code", code: "code", code_verifier: verifier, redirect_uri: `${authOrigin}/callback`, broker_ticket: brokerTicket, return_origin: applianceOrigin });
  const env = { AUTH_TICKET_HMAC_KEY: secret, GOOGLE_LOGIN_CLIENT_ID: "id", GOOGLE_LOGIN_CLIENT_SECRET: "secret" };
  const previous = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return new Response("{}", { status: 200 }); };
  try {
    for (const mutate of [
      (f) => f.set("client_secret", "caller-secret"),
      (f) => f.set("code_verifier", "wrong-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
      (f) => f.set("broker_ticket", `${brokerTicket}x`),
      (f) => f.set("return_origin", "https://attacker.example.test"),
    ]) {
      const form = new URLSearchParams(base);
      mutate(form);
      const response = await google({ env, request: new Request(`${authOrigin}/login/google/token`, { method: "POST", body: form }) });
      assert.equal(response.status, 400);
    }
    const oversized = await google({ env, request: new Request(`${authOrigin}/login/google/token`, { method: "POST", body: "x".repeat(8001) }) });
    assert.equal(oversized.status, 400);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = previous;
  }
});

test("login exchange is unavailable without host-side client secrets", async () => {
  const response = await google({ env: {}, request: new Request(`${authOrigin}/login/google/token`, { method: "POST", body: "" }) });
  assert.equal(response.status, 503);
});
