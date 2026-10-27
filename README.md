# kautuka-auth

Sign-in host for official Kautuka appliances. It creates short lived HMAC signed broker tickets after an explicit browser confirmation, adds the OAuth client id, and handles login and mail token exchange. The appliance retains the PKCE verifier. Hosted mail refresh tokens are returned only as AES-GCM envelopes and are bound to the DPoP public key thumbprint.

`public/` contains the browser pages. `functions/` contains the auth Worker routes. The `kautuka-auth` Worker exports the SQLite-backed `DpopState` Durable Object, which provides atomic DPoP nonce and jti replay protection plus permanent revoked-key tombstones. It does not persist refresh-token envelopes. One Worker deployment provisions or updates both the auth routes and the Durable Object class.

## Before deploying

1. Set Worker secrets `AUTH_TICKET_HMAC_KEY`, `REFRESH_TOKEN_KEYS`, and `REFRESH_TOKEN_ACTIVE_KID`. Generate at least 32 random bytes for the HMAC secret. `REFRESH_TOKEN_KEYS` is a JSON object mapping key ids to base64-encoded 32-byte AES keys, for example `{"k2026a":"<base64-32-byte-key>"}`. Set `REFRESH_TOKEN_ACTIVE_KID` to a key id in that map. Never store these values in source control.
2. For AES key rotation, add the new key id and key to `REFRESH_TOKEN_KEYS`, then change `REFRESH_TOKEN_ACTIVE_KID`. Keep old keys available to decrypt existing envelopes until all associated refresh tokens have been revoked or rotated; remove an old key only after that. Ticket HMAC rotation invalidates outstanding tickets, which expire after five minutes.
3. Set OAuth Worker secrets `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_ID`, and `MICROSOFT_CLIENT_SECRET` for mailbox sign-in. Appliance login uses a separate pair: `GOOGLE_LOGIN_CLIENT_ID`, `GOOGLE_LOGIN_CLIENT_SECRET`, `MICROSOFT_LOGIN_CLIENT_ID`, and `MICROSOFT_LOGIN_CLIENT_SECRET`. Non-production Workers must use their own login apps and client ids. The Microsoft login app must request both optional ID-token claims `email` and `xms_edov` (under `optionalClaims.idToken` in the app manifest). `xms_edov` lets Kautuka accept invite redemptions only when Microsoft attests that the email domain is verified.
4. Attach `auth.kautuka.io` to the `kautuka-auth` Worker. Configure its provider callback URL as exactly `https://auth.kautuka.io/callback` for each OAuth app. The ticket is carried in OAuth `state`; no callback query string is needed.

## Build and validate

```powershell
npm install
npm test
npm run build
npx wrangler deploy --dry-run
```

`npm run test:runtime` exercises the Durable Object nonce/jti race and revocation through the compiled local Worker, and checks the actual `/start/` response frame headers. Start one local Worker dev server first:

```powershell
npm run build
npx wrangler dev --local-protocol https --port 8791 --var GOOGLE_CLIENT_ID:test-client --var GOOGLE_CLIENT_SECRET:test-secret --var 'REFRESH_TOKEN_KEYS:{"k1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' --var REFRESH_TOKEN_ACTIVE_KID:k1
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

The local command disables certificate verification only for this loopback test server. `test/start-ui.test.mjs` executes the start page code with a small DOM harness to ensure the destination and purpose are shown, and no fetch or redirect occurs before the confirmation click. `npx wrangler deploy --dry-run` validates the Worker bundle and SQLite Durable Object migration without deploying. `npm run deploy` builds and deploys the single `kautuka-auth` Worker.

For Cloudflare Workers Builds, keep one Git connection to this repository with production branch `main`. Set the deploy command to `npm run deploy`, or set the build command to `npm run build` and the deploy command to `npx wrangler deploy`. Both configurations publish one Worker and provision its Durable Object class as part of that deployment.
