# kautuka-auth

Sign-in host for an official Kautuka appliance. It inserts the Google or Microsoft client id and exchanges Google and Microsoft tokens. The appliance keeps the PKCE verifier.

`public/` is the browser pages. `functions/` is compiled into the Worker. Deploy with Wrangler. The Cloudflare dashboard static upload does not run these functions.

## Before the first deploy

1. Create a KV namespace and put its id in `wrangler.jsonc` under `GOOGLE_MAIL_KEYS`.
2. Set these Worker secrets: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_ID`, and `MICROSOFT_CLIENT_SECRET`.
3. Attach `auth.kautuka.io` to this Worker. If a Worker already serves that domain, set `name` in `wrangler.jsonc` to that Worker before deploying.

## Deploy

```powershell
npm install
npm run deploy
```

`npm test` runs the function tests on this machine.
