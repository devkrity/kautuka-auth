# Contributing

Kautuka Auth is licensed under Apache-2.0. Contributions are welcome through
issues and pull requests.

## Developer Certificate of Origin

Sign off every commit with `git commit -s` to certify the Developer
Certificate of Origin (DCO) 1.1 in [DCO](DCO). If your latest commit is missing
its sign-off, fix it with `git commit --amend -s`. To sign off a series of
commits, run `git rebase --signoff main`.

## Develop and test locally

Use Node.js 26 and npm. Run these commands from the repository root:

```sh
npm ci
npm test
npm run build
npx wrangler dev --local-protocol https --port 8791
```

Configure local secrets using `.dev.vars.example`; never commit secret values.
See [SECURITY.md](SECURITY.md) to report vulnerabilities and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.
