# Kautuka Auth

This is the sign-in service Kautuka uses for Google and Microsoft login. You only need it if you run your own copy. See [Kautuka](https://github.com/devkrity/kautuka).

[![CI](https://github.com/devkrity/kautuka-auth/actions/workflows/tests.yml/badge.svg)](https://github.com/devkrity/kautuka-auth/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## How it works

The broker limits distinct new mail accounts per installation and provider over a rolling window. Defaults are 20 accounts in 30 days; operators may set `MAIL_NEW_ACCOUNT_LIMIT` (1–1000) and `MAIL_NEW_ACCOUNT_WINDOW_SECONDS` (60–31536000). Reconnecting an account already counted in the window does not consume another allowance, and disconnecting it does not erase the history. This is an abuse control, not proof that an installation is an official build. After rejection, start a new authorization when the wait has elapsed; the original provider code is never reused.

1. Kautuka registers an installation key, creates a short-lived flow and opens the broker's handoff page.
2. The browser binds the flow to its session, reviews the request and continues to Google or Microsoft. The provider returns only to the broker's fixed callback.
3. Kautuka retrieves the result using its installation key and the original PKCE verifier. Mail connections additionally use their own DPoP key and require broker admission and acknowledgement before they can refresh.

The broker stores flow, connection and replay state in the installation's Durable Object. Installation identity tracks a key; it does not prove that a caller runs an official binary. Previously published callback and token routes are retired.

For the complete Kautuka-side flow, trust boundaries, operator setup and recovery guidance, see [Authentication and mail broker](https://github.com/devkrity/kautuka/blob/main/docs/operations/authentication-broker.md).

## Local development

The repository pins Node.js with [.nvmrc](.nvmrc), and `package.json` requires Node 26. Git and Node.js are required.

### macOS and Linux (bash)

```bash
cp .dev.vars.example .dev.vars
npm ci
npm test
npm run build
npx wrangler dev
```

### Windows (PowerShell)

```powershell
Copy-Item .dev.vars.example .dev.vars
npm ci
npm test
npm run build
npx wrangler dev
```

`.dev.vars.example` contains blank placeholders. For bound-flow tests, set `BROKER_ORIGIN` to the local Worker's HTTPS origin without a trailing slash, and configure Kautuka to use the same origin. Add local OAuth credentials only if you need to test a real provider round trip. Never commit `.dev.vars`. The signing, encryption and account-identity settings include:

- `AUTH_TICKET_HMAC_KEY`: local-only random key of at least 32 bytes for ticket signatures.
- `REFRESH_TOKEN_KEYS`: JSON mapping key IDs to base64 encoded 32-byte AES keys.
- `REFRESH_TOKEN_ACTIVE_KID`: key ID selected from `REFRESH_TOKEN_KEYS` for new envelopes.
- `MAIL_ACCOUNT_PSEUDONYM_KEY`: a separate base64-encoded 32-byte key for installation-scoped mailbox identity. Back it up with the Durable Object data: replacing it without a coordinated migration changes account identities and breaks quota accounting.

The optional runtime test exercises legacy-route retirement, installation-key registration and replay rejection, and key rotation against an already-running local Wrangler Worker with its Durable Object bindings. Set `AUTH_TEST_BASE_URL` to its HTTPS loopback origin (`https://127.0.0.1:<port>`, without a trailing slash), and set the local Worker's `BROKER_ORIGIN` to the same origin. Use test-only values and a certificate trusted by Node. It does not need real provider credentials. It does not yet test the complete mail authorization lifecycle.

```bash
AUTH_TEST_BASE_URL=https://127.0.0.1:8787 npm run test:runtime
```

```powershell
$env:AUTH_TEST_BASE_URL = 'https://127.0.0.1:8787'
npm run test:runtime
```

For the separate Durable Object mail race rehearsal, start Wrangler with the local-only `test/durable/mail-harness-worker.js` entrypoint and the same loopback-origin configuration, then run `node test/durable/mail-runtime.mjs` with `AUTH_TEST_BASE_URL` set to that origin. This test invokes trusted object routes and simulates provider exchange; it is not a real OAuth test. The production router does not expose the harness route.

`npm run test:public-races` starts an isolated local Worker with the built public router and real local Durable Objects. Its test-only provider returns fake credentials without network access. It checks concurrent five-account admission and refresh racing disconnect through the public handlers; it is not a real-provider OAuth test.

For Devkrity's isolated `broker-controls` Cloudflare preview, the same registration and rotation smoke test can be run with `AUTH_TEST_CLOUDFLARE_PREVIEW=1` and `AUTH_TEST_BASE_URL=https://broker-controls-kautuka-auth.aged-star-69fb.workers.dev`. The test accepts only this explicit preview or HTTPS loopback; it does not target production. Each run creates a disposable installation identity in the preview.

## Operating your own hosted service

Operators running their own Worker configure their own OAuth applications and Worker secrets, set `BROKER_ORIGIN` to their HTTPS origin, and register that origin's `/callback` URL with each provider. The deployed rate-limit and Durable Object bindings in `wrangler.jsonc` are required. Keep encryption keys and the mailbox identity key backed up and protected; retain old encryption keys while their envelopes remain in use. See [SECURITY.md](SECURITY.md) before handling real credentials. Local development and normal Kautuka users do not deploy this service.

In Kautuka, open **Settings → Advanced → Authentication**, enter the broker's HTTPS origin and the public Google and Microsoft client IDs used for **social sign-in**, and save. Mail OAuth app IDs and secrets belong on the broker, not in those fields. Leave a social client ID blank to disable that sign-in option. Keep an active administrator with a local password, remove existing mail connections before switching origins, and restart Kautuka to apply the change. Kautuka pauses new mail sign-ins and key rotation while the change is pending; a pending change can be canceled from the same screen.

Each installation can connect up to five distinct active Google mail accounts and five distinct active Microsoft mail accounts through a broker. Disconnecting an account does not immediately revoke provider access tokens already issued; use the provider's permissions page to revoke the grant if needed. This is a breaking broker-protocol change: users with earlier mail connections may need to connect them again and may need to sign in again.

Provider approval may be required for the permissions your OAuth apps request. If the broker is unreachable, users cannot start social sign-in or connect or refresh brokered mail until it returns. After a failed disconnect, Kautuka stops local use and retains the connection details so removal can be retried. The rate limits in `wrangler.jsonc` are per IP and approximate per Cloudflare location, so shared networks can encounter them together.

Kautuka keeps a separate installation identity for each broker origin and exposes key rotation through its loopback-only, administrator-authorized maintenance endpoint `/api/internal/broker/rotate-installation-key`. Rotation retains that broker's installation ID, existing connections and account limits. If an installation key is irrecoverably lost, the installation must establish a new identity and reconnect its accounts; a claimed ID alone cannot recover it.

Creating a new identity does not revoke a stolen identity or its provider grants. A stolen installation key by itself does not provide the separately stored mail keys and credentials, but it can be used to rotate the installation key and lock out the owner. Secure the host, disconnect affected mail connections where possible, and revoke the Kautuka app's grants in the affected Google and Microsoft account settings before reconnecting. Previously issued access tokens may remain valid until expiry or provider revocation. Avoid deleting an identity beneath active credentials.

### Emergency operator suspension

The operator may permanently suspend an installation using the independent `OPERATOR_SUSPEND_SECRET` Worker secret (at least 32 random bytes encoded as unpadded base64url) and the non-secret `OPERATOR_SUSPEND_CREDENTIAL_ID` setting. Configure separate credentials for preview and production and protect the secret as a credential able to suspend any installation. The endpoint is disabled when either setting is missing; it accepts CLI requests to the configured broker origin only. There is no browser UI or reinstatement endpoint.

From a trusted operator machine, pipe the secret from a protected file into the helper; never put it in an argument or paste it into a log. For example, in PowerShell:

```powershell
Get-Content -Raw -LiteralPath '<protected-secret-file>' | node scripts/suspend-installation.mjs https://auth.kautuka.io <installation-id> key_compromised
```

The operation is permanent and idempotent. The broker records the installation ID, operation ID, reason, configured credential identifier, and time, but not the secret. A holder of the secret can suspend any installation; the credential identifier does not identify an individual person. Suspension prevents subsequent broker operations but does not revoke provider grants, invalidate provider tokens already issued, or retract responses already delivered. Ask the account owner to revoke provider grants separately. A new installation identity does not restore the suspended one.

### DPoP nonce rollout

The bound mail endpoints now require the short-lived broker nonce. The updated Gateway handles the `use_dpop_nonce` challenge and remains compatible with a broker that does not challenge it. Publish the Gateway first, then establish that the installations you intend to support have upgraded before deploying this broker version. Merely publishing the Gateway does not upgrade installed clients; older Gateways will fail their mail operations after broker enforcement begins. Explicitly choose and communicate a cutover for any clients that have not upgraded. There is no nonce-optional fallback. This nonce change does not require replacing mail credential envelopes or keys.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and pull request guidance. Sign off every commit with `git commit -s` to certify the DCO.

## License

Apache-2.0. See [LICENSE](LICENSE).
