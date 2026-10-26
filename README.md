# kautuka-auth

Sign-in host for official Kautuka appliances. It creates short lived HMAC signed broker tickets after an explicit browser confirmation, adds the OAuth client id, and handles login and mail token exchange. The appliance retains the PKCE verifier. Hosted mail refresh tokens are returned only as AES-GCM envelopes and are bound to the DPoP public key thumbprint.

`public/` contains the browser pages. `functions/` contains the Pages Worker. `dpop-state/` is the small Durable Object Worker that provides atomic DPoP nonce and jti replay protection plus permanent revoked-key tombstones. It does not persist refresh-token envelopes. Deploy the Durable Object Worker first, then the Pages Worker. Do not use static-only Pages upload.

## Before deploying

1. Create the `kautuka-auth-dpop-state` Worker from `dpop-state/wrangler.toml`, apply its first SQLite Durable Object migration, then deploy it. Keep this worker private; its default fetch handler returns 404. The Pages Worker binds to it by `script_name`.
2. Set Pages Worker secrets `AUTH_TICKET_HMAC_KEY`, `REFRESH_TOKEN_KEYS`, and `REFRESH_TOKEN_ACTIVE_KID`. Generate at least 32 random bytes for the HMAC secret. `REFRESH_TOKEN_KEYS` is a JSON object mapping key ids to base64-encoded 32-byte AES keys, for example `{"k2026a":"<base64-32-byte-key>"}`. Set `REFRESH_TOKEN_ACTIVE_KID` to a key id in that map. Never store these values in source control.
3. For AES key rotation, add the new key id and key to `REFRESH_TOKEN_KEYS`, then change `REFRESH_TOKEN_ACTIVE_KID`. Keep old keys available to decrypt existing envelopes until all associated refresh tokens have been revoked or rotated; remove an old key only after that. Ticket HMAC rotation invalidates outstanding tickets, which expire after five minutes.
4. Set OAuth Worker secrets `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_ID`, and `MICROSOFT_CLIENT_SECRET` for mailbox sign-in. Appliance login uses a separate pair: `GOOGLE_LOGIN_CLIENT_ID`, `GOOGLE_LOGIN_CLIENT_SECRET`, `MICROSOFT_LOGIN_CLIENT_ID`, and `MICROSOFT_LOGIN_CLIENT_SECRET`. Non-production Workers must use their own login apps and client ids. The Microsoft login app must include the optional `email` claim.
5. Attach `auth.kautuka.io` to this Pages Worker. Configure its provider callback URL as exactly `https://auth.kautuka.io/callback` for each OAuth app. The ticket is carried in OAuth `state`; no callback query string is needed.

## Build and validate

```powershell
npm install
npm test
npm run build
npm run build:state
```

`npm run test:runtime` exercises the Durable Object nonce/jti race and revocation through the compiled local Pages Worker, and checks the actual `/start/` response frame headers. Start the Durable Object and Pages dev servers in separate terminals first:

```powershell
npx wrangler dev --config dpop-state/wrangler.toml --port 8790
npx wrangler pages dev public --local-protocol https --port 8791 --binding GOOGLE_CLIENT_ID=test-client --binding GOOGLE_CLIENT_SECRET=test-secret --binding REFRESH_TOKEN_KEYS='{"k1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' --binding REFRESH_TOKEN_ACTIVE_KID=k1
$previousAuthTestBaseUrl = $env:AUTH_TEST_BASE_URL
$previousTlsVerification = $env:NODE_TLS_REJECT_UNAUTHORIZED
try {
  $env:AUTH_TEST_BASE_URL = 'https://127.0.0.1:8791'
  $env:NODE_TLS_REJECT_UNAUTHORIZED = '0'
  npm run test:runtime
} finally {
  $env:AUTH_TEST_BASE_URL = $previousAuthTestBaseUrl
  $env:NODE_TLS_REJECT_UNAUTHORIZED = $previousTlsVerification
}
```

The local command disables certificate verification only for this loopback test server. `test/start-ui.test.mjs` executes the start page code with a small DOM harness to ensure the destination and purpose are shown, and no fetch or redirect occurs before the confirmation click. `npm run build:state` is a dry run. `npm run deploy` performs a Pages Worker deploy and is not part of local validation.
