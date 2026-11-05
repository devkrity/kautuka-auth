// Test-only local broker for Gateway process-restart acceptance.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { unstable_startWorker } from 'wrangler';

const [portText, certPath, keyPath] = process.argv.slice(2);
const port = Number(portText);
if (!Number.isInteger(port) || port < 1024 || port > 65535 || !certPath || !keyPath) throw new Error('Local port, certificate and key are required.');
const origin = `https://localhost:${port}`;
const directory = await mkdtemp(join(tmpdir(), 'kautuka-gated-broker-'));
const config = JSON.parse(await readFile(resolve('wrangler.jsonc'), 'utf8'));
config.main = resolve('test/durable/public-provider-worker.js');
config.assets.directory = resolve('public');
delete config.previews;
config.vars = { BROKER_ORIGIN: origin, AUTH_TICKET_HMAC_KEY: 'local-test-only-not-a-production-secret',
  REFRESH_TOKEN_KEYS: JSON.stringify({ active: Buffer.alloc(32, 5).toString('base64') }), REFRESH_TOKEN_ACTIVE_KID: 'active',
  MAIL_ACCOUNT_PSEUDONYM_KEY: Buffer.alloc(32, 6).toString('base64'), GOOGLE_CLIENT_ID: 'local-client', GOOGLE_CLIENT_SECRET: 'local-secret' };
const configPath = join(directory, 'wrangler.json');
await writeFile(configPath, JSON.stringify(config));
let worker;
try {
  worker = await unstable_startWorker({ name: 'kautuka-local-gated-broker', entrypoint: config.main, config: configPath,
    dev: { persist: false, server: { hostname: '127.0.0.1', port, secure: true, httpsCertPath: certPath, httpsKeyPath: keyPath } } });
  console.log(`LOCAL_BROKER_READY ${origin}`);
  await new Promise(resolve => { process.once('SIGINT', resolve); process.once('SIGTERM', resolve); process.stdin.resume(); process.stdin.once('end', resolve); });
} finally {
  if (worker) await worker.dispose();
  if (resolve(dirname(directory)) !== resolve(tmpdir()) || !basename(directory).startsWith('kautuka-gated-broker-'))
    throw new Error('Refusing to remove a directory outside the local test workspace.');
  await rm(directory, { recursive: true, force: true });
}
