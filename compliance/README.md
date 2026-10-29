# Release third-party compliance

`kautuka-auth` is deployed as a Cloudflare Worker from `main`; this repository does not currently build a customer download or container image. The compliance workflow runs the same check on pull requests and every push to `main`, builds the Worker bundle, and uploads SPDX SBOMs for the bundle and the resolved npm build dependencies installed on the Linux runner from the lockfile.

The reviewed inventory currently records no third-party npm runtime dependencies. Wrangler is a development/build dependency and is included in the build-dependencies SBOM, not represented as a Worker runtime dependency. The generator fails when a third-party runtime package is added without a matching source/version/license record in `third-party-components.json`.

The workflow artifacts are retained for 90 days. When tagged releases or a public downloadable Worker bundle are introduced, publish that release's notices, inventory, and SBOM alongside it and retain those materials for as long as the corresponding build is distributed.
