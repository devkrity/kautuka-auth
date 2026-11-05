// Local-only test of the built public router and real Durable Objects. Provider
// responses are provided by a local-only Worker entrypoint which never forwards
// outbound requests; no traffic is sent to Google or Microsoft.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { resolve, join, dirname, basename } from 'node:path';
import { unstable_startWorker } from 'wrangler';

const enc = value => Buffer.from(value).toString('base64url');
const random = () => enc(randomBytes(32));
const hash = async value => enc(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
const portProbe = createServer();
await new Promise((resolve, reject) => portProbe.listen(0, '127.0.0.1', resolve).once('error', reject));
const port = portProbe.address().port;
await new Promise((resolve, reject) => portProbe.close(error => error ? reject(error) : resolve()));
const origin = `https://127.0.0.1:${port}`;
const directory = await mkdtemp(join(tmpdir(), 'kautuka-public-races-'));
const config = JSON.parse(await readFile(resolve('wrangler.jsonc'), 'utf8'));
config.main = resolve('test/durable/public-provider-worker.js');
config.assets.directory = resolve('public');
delete config.previews;
config.vars = {
  BROKER_ORIGIN: origin,
  AUTH_TICKET_HMAC_KEY: 'local-test-only-not-a-production-secret',
  REFRESH_TOKEN_KEYS: JSON.stringify({ active: Buffer.alloc(32, 5).toString('base64') }),
  REFRESH_TOKEN_ACTIVE_KID: 'active',
  MAIL_ACCOUNT_PSEUDONYM_KEY: Buffer.alloc(32, 6).toString('base64'),
  GOOGLE_CLIENT_ID: 'local-client', GOOGLE_CLIENT_SECRET: 'local-secret',
  MICROSOFT_CLIENT_ID: 'local-ms-client', MICROSOFT_CLIENT_SECRET: 'local-ms-secret',
  OPERATOR_SUSPEND_SECRET: 'o'.repeat(43), OPERATOR_SUSPEND_CREDENTIAL_ID: 'local-test',
};
const configPath = join(directory, 'wrangler.json');
await writeFile(configPath, JSON.stringify(config));
let worker;
let pendingRefresh;
try {
  const startWorker = () => unstable_startWorker({ name: 'kautuka-local-public-races', entrypoint: config.main, config: configPath,
    dev: { persist: join(directory, 'state'), server: { hostname: '127.0.0.1', port, secure: true } } });
  worker = await startWorker();
  const id = random(), key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  let lastDpop;
  async function signed(path, body, dpopKey, reusedDpop, nonce, rawChallenge = false) {
    const target = `${origin}${path}`, bytes = JSON.stringify(body), pub = await crypto.subtle.exportKey('jwk', key.publicKey);
    const header = enc(JSON.stringify({ typ: 'kautuka-installation+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } }));
    const now = Math.floor(Date.now() / 1000);
    const claims = enc(JSON.stringify({ aud: origin, htm: 'POST', htu: target, iat: now, exp: now + 60, jti: random(), body_hash: await hash(bytes) }));
    const input = `${header}.${claims}`;
    const sig = enc(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(input)));
    const headers = { 'content-type': 'application/json', 'CF-Connecting-IP': '127.0.0.1',
      'Kautuka-Installation-Proof': `${input}.${sig}` };
    if (dpopKey) {
      const pub = await crypto.subtle.exportKey('jwk', dpopKey.publicKey);
      const h = enc(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } }));
      const c = enc(JSON.stringify({ htm: 'POST', htu: target, iat: now, jti: random(), ...(nonce ? { nonce } : {}) }));
      const signature = enc(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, dpopKey.privateKey, new TextEncoder().encode(`${h}.${c}`)));
      headers.DPoP = reusedDpop ?? `${h}.${c}.${signature}`;
      lastDpop = headers.DPoP;
    }
    const response = await worker.fetch(target, { method: 'POST', headers, body: bytes });
    if (dpopKey && !reusedDpop && !nonce && !rawChallenge && response.status === 400 && response.headers.has('dpop-nonce')) {
      assert.deepEqual(await response.json(), { error: 'use_dpop_nonce' });
      return signed(path, body, dpopKey, undefined, response.headers.get('dpop-nonce'));
    }
    return response;
  }
  async function browser(path, body, cookie) {
    return worker.fetch(`${origin}${path}`, { method: 'POST', headers: { origin, 'content-type': 'application/json',
      'CF-Connecting-IP': '127.0.0.1', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  }
  const response = await signed('/installation/register', { id });
  assert.equal(response.status, 204, 'public signed registration');
  async function prepare(code = `local-${random()}`, provider = 'google') {
    const dpop = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pub = await crypto.subtle.exportKey('jwk', dpop.publicKey);
    const dpopJkt = await hash(JSON.stringify({ crv: 'P-256', kty: 'EC', x: pub.x, y: pub.y }));
    const verifier = random(), connectionId = random(), state = random();
    const start = await signed('/installation/flow', { id, provider, purpose: 'mail', state,
      challenge: await hash(verifier), nonce: random(), gatewayOrigin: 'http://localhost:20229', connectionId, dpopJkt, expectedGeneration: 0 });
    assert.equal(start.status, 200, 'create flow');
    const { flowId } = await start.json();
    const candidate = await browser('/handoff/candidate', { id, flowId });
    assert.equal(candidate.status, 200, 'browser candidate');
    const cookie = candidate.headers.get('set-cookie').split(';')[0];
    const { nonce } = await candidate.json();
    assert.equal((await signed('/installation/bind-browser', { id, flowId, nonce })).status, 204, 'bind browser');
    const authorization = await browser('/handoff/authorize', { id, flowId }, cookie);
    assert.equal(authorization.status, 200, 'authorize');
    const providerState = new URL((await authorization.json()).authorizeUrl).searchParams.get('state');
    assert.equal((await browser('/handoff/callback', { state: providerState, code }, cookie)).status, 204, 'callback');
    return { dpop, flowId, verifier, connectionId };
  }
  const partial = await prepare('local-insufficient');
  const partialPayload = { id, flowId: partial.flowId, verifier: partial.verifier };
  const beforeChallenge = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges;
  const wrongKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const wrongKeyChallenge = await signed('/installation/mail-exchange', partialPayload, wrongKey, undefined, undefined, true);
  assert.equal(wrongKeyChallenge.status, 400, 'a different mailbox key must negotiate its own nonce first');
  assert.deepEqual(await wrongKeyChallenge.json(), { error: 'use_dpop_nonce' });
  const wrongKeyResult = await signed('/installation/mail-exchange', partialPayload, wrongKey, undefined, wrongKeyChallenge.headers.get('dpop-nonce'));
  assert.equal(wrongKeyResult.status, 409, 'a valid nonce does not authorize the wrong mailbox key');
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, beforeChallenge,
    'the wrong mailbox key must not invoke the provider');
  const challenge = await signed('/installation/mail-exchange', partialPayload, partial.dpop, undefined, undefined, true);
  assert.equal(challenge.status, 400);
  assert.deepEqual(await challenge.json(), { error: 'use_dpop_nonce' });
  assert.match(challenge.headers.get('dpop-nonce'), /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, beforeChallenge,
    'a nonce challenge cannot invoke the provider');
  const wrongNonce = await signed('/installation/mail-exchange', partialPayload, partial.dpop, undefined, random());
  assert.equal(wrongNonce.status, 400, 'a signed proof with a wrong nonce is challenged');
  assert.deepEqual(await wrongNonce.json(), { error: 'use_dpop_nonce' });
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, beforeChallenge,
    'a wrong nonce cannot invoke the provider');
  const commonChallenge = { id, provider: 'google', connectionId: partial.connectionId, flowId: partial.flowId, generation: 1 };
  for (const [path, payload] of [
    ['/installation/mail-ack', partialPayload],
    ['/installation/mail-status', commonChallenge],
    ['/installation/mail-cancel', { id, flowId: partial.flowId }],
    ['/installation/mail-disconnect', commonChallenge],
    ['/installation/mail-refresh', { ...commonChallenge, operationId: random(), refreshToken: 'kmf1.' + 'x'.repeat(40) }],
    ['/installation/mail-refresh-ack', { ...commonChallenge, operationId: random() }],
  ]) {
    const rejected = await signed(path, payload, partial.dpop, undefined, undefined, true);
    assert.equal(rejected.status, 400, `${path} requires a nonce`);
    assert.deepEqual(await rejected.json(), { error: 'use_dpop_nonce' });
  }
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, beforeChallenge,
    'nonce challenges cannot mutate the pending exchange');
  const rejected = await signed('/installation/mail-exchange', partialPayload, partial.dpop);
  assert.equal(rejected.status, 403, 'partial grant is not admitted');
  assert.equal(rejected.headers.get('kautuka-mail-error'), 'insufficient_scope');
  // The client may lose this terminal response. Recreate the Worker with the
  // same durable data before retrying, using fresh installation and DPoP proofs.
  await worker.dispose();
  worker = await startWorker();
  const callsAfterRejection = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges;
  const partialRetry = await signed('/installation/mail-exchange', partialPayload, partial.dpop);
  assert.equal(partialRetry.status, 403, 'partial grant remains unusable on retry');
  assert.equal(partialRetry.headers.get('kautuka-mail-error'), 'insufficient_scope');
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, callsAfterRejection);
  const microsoftPartial = await prepare('local-ms-insufficient', 'microsoft');
  const microsoftPayload = { id, flowId: microsoftPartial.flowId, verifier: microsoftPartial.verifier };
  const microsoftRejected = await signed('/installation/mail-exchange', microsoftPayload, microsoftPartial.dpop);
  assert.equal(microsoftRejected.status, 403, 'partial Microsoft grant is not admitted');
  assert.equal(microsoftRejected.headers.get('kautuka-mail-error'), 'insufficient_scope');
  const callsAfterMicrosoft = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges;
  const microsoftRetry = await signed('/installation/mail-exchange', microsoftPayload, microsoftPartial.dpop);
  assert.equal(microsoftRetry.status, 403);
  assert.equal(microsoftRetry.headers.get('kautuka-mail-error'), 'insufficient_scope');
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, callsAfterMicrosoft);
  const microsoftFlow = await prepare('local-ms-valid', 'microsoft');
  const microsoftExchange = await signed('/installation/mail-exchange', { id, flowId: microsoftFlow.flowId, verifier: microsoftFlow.verifier }, microsoftFlow.dpop);
  assert.equal(microsoftExchange.status, 200);
  const microsoftCredential = await microsoftExchange.json();
  assert.equal((await signed('/installation/mail-ack', { id, flowId: microsoftFlow.flowId, verifier: microsoftFlow.verifier }, microsoftFlow.dpop)).status, 204);
  const microsoftCommon = { id, provider: 'microsoft', connectionId: microsoftFlow.connectionId, flowId: microsoftFlow.flowId, generation: microsoftCredential.generation };
  const microsoftRefresh = { ...microsoftCommon, operationId: random(), refreshToken: microsoftCredential.refreshToken };
  assert.equal((await worker.fetch(`${origin}/__test_ack_arm`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ flowId: microsoftFlow.flowId }) })).status, 204);
  pendingRefresh = signed('/installation/mail-refresh', microsoftRefresh, microsoftFlow.dpop);
  await waitForRefresh();
  assert.equal((await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' })).status, 204);
  const microsoftRefreshResult = await pendingRefresh;
  pendingRefresh = undefined;
  assert.equal(microsoftRefreshResult.status, 403, 'partial Microsoft refresh must not deliver a rotated token');
  assert.equal(microsoftRefreshResult.headers.get('kautuka-mail-error'), 'insufficient_scope');
  // Simulate the caller losing the response, then recreate the Worker and its
  // Durable Object from disk before retrying with fresh signed proofs.
  await worker.dispose();
  worker = await startWorker();
  const microsoftRefreshCalls = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).refreshes;
  for (const operationId of [microsoftRefresh.operationId, random()]) {
    const repeated = await signed('/installation/mail-refresh', { ...microsoftRefresh, operationId }, microsoftFlow.dpop);
    assert.equal(repeated.status, 403);
    assert.equal(repeated.headers.get('kautuka-mail-error'), 'insufficient_scope');
  }
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).refreshes, microsoftRefreshCalls);
  assert.equal((await signed('/installation/mail-disconnect', microsoftCommon, microsoftFlow.dpop)).status, 204);
  const flows = await Promise.all(Array.from({ length: 6 }, () => prepare()));
  const exchanges = await Promise.all(flows.map(async flow => {
    const response = await signed('/installation/mail-exchange', { id, flowId: flow.flowId, verifier: flow.verifier }, flow.dpop);
    const credential = response.status === 200 ? await response.json() : undefined;
    return { response, credential };
  }));
  const responses = exchanges.map(exchange => exchange.response);
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 200, 200, 200, 200, 409], 'five mailboxes admitted and sixth rejected');
  assert.equal(responses.find(r => r.status === 409).headers.get('kautuka-admission-denied'), 'active_account_limit');
  const denied = flows[responses.findIndex(r => r.status === 409)];
  const beforeRetry = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges;
  const retry = await signed('/installation/mail-exchange', { id, flowId: denied.flowId, verifier: denied.verifier }, denied.dpop);
  assert.equal(retry.status, 409, 'sixth admission remains terminal');
  assert.equal(retry.headers.get('kautuka-admission-denied'), 'active_account_limit');
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).exchanges, beforeRetry,
    'terminal retry must not exchange the provider code again');
  const admitted = responses.map((response, index) => response.status === 200 ? index : -1).filter(index => index >= 0);
  const partialIndex = admitted[0], partialFlow = flows[partialIndex], partialCredential = exchanges[partialIndex].credential;
  assert.equal((await signed('/installation/mail-ack', { id, flowId: partialFlow.flowId, verifier: partialFlow.verifier }, partialFlow.dpop)).status, 204);
  const partialCommon = { id, provider: 'google', connectionId: partialFlow.connectionId, flowId: partialFlow.flowId, generation: partialCredential.generation };
  const partialRefresh = { ...partialCommon, operationId: random(), refreshToken: partialCredential.refreshToken };
  assert.equal((await worker.fetch(`${origin}/__test_partial_refresh`, { method: 'POST' })).status, 204);
  pendingRefresh = signed('/installation/mail-refresh', partialRefresh, partialFlow.dpop);
  await waitForRefresh();
  assert.equal((await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' })).status, 204);
  const partialResult = await pendingRefresh;
  pendingRefresh = undefined;
  assert.equal(partialResult.status, 403, 'partial refresh must not deliver a token');
  assert.equal(partialResult.headers.get('kautuka-mail-error'), 'insufficient_scope');
  const partialRefreshCalls = (await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).refreshes;
  for (const operationId of [partialRefresh.operationId, random()]) {
    const retry = await signed('/installation/mail-refresh', { ...partialRefresh, operationId }, partialFlow.dpop);
    assert.equal(retry.status, 403, 'partial refresh remains terminal');
    assert.equal(retry.headers.get('kautuka-mail-error'), 'insufficient_scope');
  }
  assert.equal((await (await worker.fetch(`${origin}/__test_provider_stats`)).json()).refreshes, partialRefreshCalls,
    'partial refresh retries must not call the provider again');
  assert.equal((await signed('/installation/mail-disconnect', partialCommon, partialFlow.dpop)).status, 204);
  const index = admitted[1], flow = flows[index], credential = exchanges[index].credential;
  assert.equal((await signed('/installation/mail-ack', { id, flowId: flow.flowId, verifier: flow.verifier }, flow.dpop)).status, 204, 'acknowledge mailbox');
  const common = { id, provider: 'google', connectionId: flow.connectionId, flowId: flow.flowId, generation: credential.generation };
  assert.deepEqual(await (await signed('/installation/mail-status', common, flow.dpop)).json(), { active: true });
  const usedDpop = lastDpop;
  assert.equal((await signed('/installation/mail-status', common, flow.dpop, usedDpop)).status, 403,
    'a fresh installation proof cannot replay a consumed DPoP proof');
  // Reset the local fake's observation flag without enabling its failure mode.
  assert.equal((await worker.fetch(`${origin}/__test_ack_arm`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ flowId: flow.flowId }) })).status, 204);
  pendingRefresh = signed('/installation/mail-refresh', { ...common, operationId: random(), refreshToken: credential.refreshToken }, flow.dpop);
  await waitForRefresh();
  assert.equal((await signed('/installation/mail-disconnect', common, flow.dpop)).status, 204, 'disconnect during refresh');
  assert.equal((await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' })).status, 204, 'release provider response');
  assert.equal((await pendingRefresh).status, 409, 'late refresh must not publish credentials');
  assert.deepEqual(await (await signed('/installation/mail-status', common, flow.dpop)).json(), { active: false }, 'disconnect remains durable');
  assert.equal((await signed('/installation/mail-refresh', { ...common, operationId: random(), refreshToken: credential.refreshToken }, flow.dpop)).status,
    409, 'a new refresh cannot use the disconnected credential');
  const racedFlow = flows[admitted[2]], racedCredential = exchanges[admitted[2]].credential;
  assert.equal((await signed('/installation/mail-ack', { id, flowId: racedFlow.flowId, verifier: racedFlow.verifier }, racedFlow.dpop)).status, 204);
  const racedCommon = { id, provider: 'google', connectionId: racedFlow.connectionId, flowId: racedFlow.flowId, generation: racedCredential.generation };
  assert.equal((await worker.fetch(`${origin}/__test_partial_refresh`, { method: 'POST' })).status, 204);
  pendingRefresh = signed('/installation/mail-refresh', { ...racedCommon, operationId: random(), refreshToken: racedCredential.refreshToken }, racedFlow.dpop);
  await waitForRefresh();
  assert.equal((await signed('/installation/mail-disconnect', racedCommon, racedFlow.dpop)).status, 204);
  assert.equal((await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' })).status, 204);
  assert.equal((await pendingRefresh).status, 409, 'partial-scope failure cannot revive a disconnected connection');
  assert.deepEqual(await (await signed('/installation/mail-status', racedCommon, racedFlow.dpop)).json(), { active: false });
  const suspendedFlow = flows[admitted[3]], suspendedCredential = exchanges[admitted[3]].credential;
  assert.equal((await signed('/installation/mail-ack', { id, flowId: suspendedFlow.flowId, verifier: suspendedFlow.verifier }, suspendedFlow.dpop)).status, 204);
  const suspendedCommon = { id, provider: 'google', connectionId: suspendedFlow.connectionId, flowId: suspendedFlow.flowId, generation: suspendedCredential.generation };
  const pendingFlow = await prepare('local-suspended-exchange');
  const pendingExchange = signed('/installation/mail-exchange', { id, flowId: pendingFlow.flowId, verifier: pendingFlow.verifier }, pendingFlow.dpop);
  const exchangeDeadline = Date.now() + 10000;
  while (!(await (await worker.fetch(`${origin}/__test_exchange_started`)).json()).exchangeStarted) {
    assert.ok(Date.now() < exchangeDeadline, 'provider exchange was reached');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal((await worker.fetch(`${origin}/__test_refresh_rearm`, { method: 'POST' })).status, 204);
  pendingRefresh = signed('/installation/mail-refresh', { ...suspendedCommon, operationId: random(), refreshToken: suspendedCredential.refreshToken }, suspendedFlow.dpop);
  await waitForRefresh();
  const suspendBody = JSON.stringify({ id, operationId: random(), reason: 'test_compromise' });
  const suspend = () => worker.fetch(`${origin}/operator/installations/suspend`, { method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '127.0.0.1', authorization: `Bearer ${'o'.repeat(43)}` }, body: suspendBody });
  const unauthorizedSuspend = await worker.fetch(`${origin}/operator/installations/suspend`, { method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '127.0.0.1', authorization: `Bearer ${'x'.repeat(43)}` }, body: suspendBody });
  assert.equal(unauthorizedSuspend.status, 403);
  const browserSuspend = await worker.fetch(`${origin}/operator/installations/suspend`, { method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '127.0.0.1', origin: 'https://attacker.example', authorization: `Bearer ${'o'.repeat(43)}` }, body: suspendBody });
  assert.equal(browserSuspend.status, 403);
  assert.equal((await (await suspend()).json()).status, 'suspended');
  assert.equal((await (await suspend()).json()).status, 'already_suspended');
  assert.equal((await worker.fetch(`${origin}/__test_exchange_release`, { method: 'POST' })).status, 204);
  assert.equal((await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' })).status, 204);
  const lateExchange = await pendingExchange;
  const lateRefresh = await pendingRefresh;
  assert.equal(lateExchange.status, 409, 'suspension prevents an in-flight exchange result from being delivered');
  assert.equal(lateRefresh.status, 503, 'suspension prevents an in-flight refresh result from being delivered');
  for (const result of [lateExchange, lateRefresh]) assert.doesNotMatch(await result.text(), /local-(?:access|refresh|next-refresh)/);
  const exchangeRetry = await signed('/installation/mail-exchange', { id, flowId: pendingFlow.flowId, verifier: pendingFlow.verifier }, pendingFlow.dpop);
  assert.equal(exchangeRetry.status, 403);
  assert.equal(exchangeRetry.headers.get('kautuka-installation-error'), 'installation_suspended');
  const suspendedRegistration = await signed('/installation/register', { id });
  assert.equal(suspendedRegistration.status, 403, 'suspension prevents re-registration');
  assert.equal(suspendedRegistration.headers.get('kautuka-installation-error'), 'installation_suspended');
  const suspendedStatus = await signed('/installation/mail-status', suspendedCommon, suspendedFlow.dpop);
  assert.equal(suspendedStatus.status, 403);
  assert.equal(suspendedStatus.headers.get('kautuka-installation-error'), 'installation_suspended');
  const suspendedFlowStart = await signed('/installation/flow', { id, provider: 'google', purpose: 'login', state: random(), challenge: random(), nonce: random(), gatewayOrigin: 'http://localhost:20229' });
  assert.equal(suspendedFlowStart.status, 403);
  assert.equal(suspendedFlowStart.headers.get('kautuka-installation-error'), 'installation_suspended');
  console.log('Public handlers with real local Durable Objects admitted five of six mailboxes and rejected refresh after disconnect.');
  async function waitForRefresh() {
    const deadline = Date.now() + 10000;
    let started = false;
    while (Date.now() < deadline && !started) {
      started = (await (await worker.fetch(`${origin}/__test_refresh_started`)).json()).refreshStarted;
      if (!started) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.ok(started, 'provider refresh was reached');
  }
} finally {
  if (worker && pendingRefresh) {
    // Release the fake provider even if an intermediate assertion failed.
    try { await worker.fetch(`${origin}/__test_refresh_release`, { method: 'POST' }); } catch { /* Worker may already be stopping. */ }
    await Promise.race([pendingRefresh.catch(() => {}), new Promise(resolve => setTimeout(resolve, 2000))]);
  }
  if (worker) await worker.dispose();
  if (resolve(dirname(directory)) !== resolve(tmpdir()) || !basename(directory).startsWith('kautuka-public-races-'))
    throw new Error('Refusing to remove a directory outside the local test workspace.');
  await rm(directory, { recursive: true, force: true });
}
