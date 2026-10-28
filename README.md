# Kautuka Auth

This is the sign-in service Kautuka uses for Google and Microsoft login. You only need it if you run your own copy. See [Kautuka](https://github.com/devkrity/kautuka).

[![CI](https://github.com/devkrity/kautuka-auth/actions/workflows/tests.yml/badge.svg)](https://github.com/devkrity/kautuka-auth/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## How it works

1. Kautuka creates a one-time PKCE challenge and sends the user to `/start/` with the connector, return URL, state, and challenge.
2. The user reviews the requested sign-in and confirms it in the browser. `POST /start/confirm` issues a short-lived signed ticket.
3. The browser visits `/authorize` with that ticket. This service starts the provider OAuth flow and keeps the ticket in OAuth state.
4. The provider returns to the `/callback` browser page. It validates the ticket with `/callback/validate`, then returns the provider result to Kautuka.
5. Kautuka completes login through the provider-specific login token route. For mail connectors, Kautuka exchanges tokens at the provider route and receives refresh credentials only as an encrypted envelope bound to its DPoP key.

The appliance retains the PKCE verifier. The Worker stores DPoP nonce and replay state in its SQLite-backed `DpopState` Durable Object.

### Routes

| Route | Method | Purpose |
| --- | --- | --- |
| `/start/` | GET | Display the connection confirmation page. |
| `/start/confirm` | POST | Validate the browser confirmation and issue a ticket. |
| `/authorize` | GET | Begin the selected provider OAuth flow. |
| `/callback` | GET | Handle the provider redirect in the browser. |
| `/callback/validate` | POST | Validate the ticket before returning the provider result to Kautuka. |
| `/login/google/token` | POST | Exchange the Google login authorization code. |
| `/login/microsoft/token` | POST | Exchange the Microsoft login authorization code. |
| `/google-mail/token` | POST | Exchange Google mail authorization and encrypted refresh token. |
| `/google-mail/keys/:jkt` | DELETE | Revoke a registered Google mail DPoP key. |
| `/microsoft-mail/token` | POST | Exchange Microsoft mail authorization and encrypted refresh token. |
| `/microsoft-mail/keys/:jkt` | DELETE | Revoke a registered Microsoft mail DPoP key. |

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

`.dev.vars.example` contains blank placeholders. Add local OAuth credentials only if you need to test a real provider round trip. Never commit `.dev.vars`. The three signing/encryption settings are needed for token exchange:

- `AUTH_TICKET_HMAC_KEY`: local-only random key of at least 32 bytes for ticket signatures.
- `REFRESH_TOKEN_KEYS`: JSON mapping key IDs to base64 encoded 32-byte AES keys.
- `REFRESH_TOKEN_ACTIVE_KID`: key ID selected from `REFRESH_TOKEN_KEYS` for new envelopes.

The optional runtime test exercises DPoP nonce replay and key revocation against an already-running local Wrangler Worker. Set `AUTH_TEST_BASE_URL` to its HTTPS loopback URL (`https://127.0.0.1:<port>`); use test-only values and a certificate trusted by Node. It does not need real provider credentials.

```bash
AUTH_TEST_BASE_URL=https://127.0.0.1:8787 npm run test:runtime
```

```powershell
$env:AUTH_TEST_BASE_URL = 'https://127.0.0.1:8787'
npm run test:runtime
```

## Operating your own hosted service

Only operators running their own Worker need to configure production OAuth applications, Worker secrets, the `auth.kautuka.io` custom domain, and provider callback URL `https://auth.kautuka.io/callback`. See [SECURITY.md](SECURITY.md) before handling real credentials. Local development and normal Kautuka users do not deploy this service.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and pull request guidance. Sign off every commit with `git commit -s` to certify the DCO.

## License

Apache-2.0. See [LICENSE](LICENSE).
