import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/suspend-installation.mjs", import.meta.url));
const id = "a".repeat(43), secret = "s".repeat(43);
const mock = `globalThis.fetch = async (url, options) => {
  const body = JSON.parse(options.body);
  if (url !== 'https://broker.example/operator/installations/suspend' || options.redirect !== 'error'
    || options.headers.authorization !== 'Bearer ${secret}' || body.id !== '${id}' || body.reason !== 'key_compromised'
    || !/^[A-Za-z0-9_-]{43}$/.test(body.operationId)) throw new Error('unexpected request');
  return new Response(JSON.stringify({status:'suspended'}), {status:200});
}`;
const preload = `data:text/javascript,${encodeURIComponent(mock)}`;

test("operator CLI reads its secret from stdin and sends a bounded suspension request", () => {
  const result = spawnSync(process.execPath, ["--import", preload, script, "https://broker.example", id, "key_compromised"], { input: `${secret}\n`, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /suspended/);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
});

test("operator CLI rejects missing credentials before making a request", () => {
  const result = spawnSync(process.execPath, ["--import", preload, script, "https://broker.example", id, "key_compromised"], { input: "", encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid operator secret input/);
  assert.doesNotMatch(result.stderr, /unexpected request/);
});
