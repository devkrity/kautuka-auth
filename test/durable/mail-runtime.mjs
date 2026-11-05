import assert from 'node:assert/strict';

const origin = process.env.AUTH_TEST_BASE_URL;
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(origin ?? '')) throw new Error('Use an isolated loopback Wrangler harness.');
const encode = value => Buffer.from(value).toString('base64url');
const random = () => encode(crypto.getRandomValues(new Uint8Array(32)));
const hash = async value => encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
const id = random(), thumbprint = random(), verifier = random(), challenge = await hash(verifier), dpopJkt = random();
const proof = () => ({ thumbprint, jti: random(), expiresAt: Date.now() + 60000 });
async function invoke(path, body) {
  return fetch(`${origin}/__local_test_object`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-local-test': 'local-durable-test' },
    body: JSON.stringify({ id, path, body }) });
}
assert.equal((await invoke('/register', proof())).status, 204);
async function prepare() {
  const state = random(), connection = random();
  const start = await invoke('/create-flow', { ...proof(), flow: { provider: 'google', purpose: 'mail', state, challenge,
    nonce: random(), gatewayOrigin: 'http://localhost:20229', connectionId: connection, dpopJkt, expectedGeneration: 0 } });
  assert.equal(start.status, 200);
  const { flowId } = await start.json(), cookieHash = random();
  const candidate = await (await invoke('/browser-candidate', { flowId, cookieHash })).json();
  assert.equal((await invoke('/bind-browser', { ...proof(), flowId, nonce: candidate.nonce })).status, 204);
  assert.equal((await invoke('/start-provider', { flowId, cookieHash })).status, 200);
  assert.equal((await invoke('/provider-callback', { flowId, cookieHash, state, result: { code: 'test-code' } })).status, 204);
  const claimed = await invoke('/claim-mail-exchange', { ...proof(), flowId, verifier, dpopJkt, dpopFingerprint: random(), allowedProviders: ['google'] });
  assert.equal(claimed.status, 200);
  const credentialEnvelope = `kmf1.${random()}`, credentialHash = await hash(credentialEnvelope);
  return { flowId, connection, credentialEnvelope, credentialHash, account: random(), sealedResult: `sealed.${random()}` };
}
const attempts = await Promise.all(Array.from({ length: 6 }, prepare));
const decisions = await Promise.all(attempts.map(flow => invoke('/finish-mail-exchange', flow)));
assert.equal(decisions.filter(result => result.status === 200).length, 5);
assert.equal(decisions.filter(result => result.status === 409).length, 1);
const acceptedIndex = decisions.findIndex(result => result.status === 200);
const accepted = attempts[acceptedIndex], { generation } = await decisions[acceptedIndex].json();
assert.equal((await invoke('/ack-mail-exchange', { ...proof(), flowId: accepted.flowId, verifier, dpopJkt, dpopFingerprint: random() })).status, 204);
const operationId = random();
const refresh = { provider: 'google', connection: accepted.connection, flowId: accepted.flowId, generation,
  dpopJkt, operationId, credentialHash: accepted.credentialHash };
const claim = await invoke('/claim-mail-refresh', { ...proof(), ...refresh, dpopFingerprint: random() });
assert.equal((await claim.json()).status, 'claimed');
assert.equal((await invoke('/disconnect-mail', { ...proof(), provider: 'google', connectionId: accepted.connection,
  flowId: accepted.flowId, generation, dpopJkt, dpopFingerprint: random() })).status, 204);
const nextCredentialEnvelope = `kmf1.${random()}`;
assert.equal((await invoke('/finish-mail-refresh', { ...refresh, nextCredentialEnvelope,
  nextCredentialHash: await hash(nextCredentialEnvelope), sealedResult: `sealed.${random()}` })).status, 409);
console.log('Real Durable Object admitted five of six accounts and rejected a refresh result after disconnect.');
