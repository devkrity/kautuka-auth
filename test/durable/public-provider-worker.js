// Test-only entrypoint. It never forwards fetches to the internet.
import authWorker from '../../dist/worker/index.js';
export { DpopState } from '../../dpop-state/src/index.js';
export { InstallationState } from '../../installation-state/src/index.js';

let account = 0;
let refreshStarted = false;
let releaseRefresh;
let failRefresh = false;
let partialRefresh = false;
let exchanges = 0;
let exchangeStarted = false;
let releaseExchange;
let gateAck = false;
let gateFlowId;
let gatePath = '/installation/mail-ack';
let ackCommitted = false;
let releaseAck;
let acknowledgements = 0;
let disconnections = 0;
let refreshes = 0;
globalThis.fetch = async (url, init = {}) => {
  if (String(url) === 'https://login.microsoftonline.com/common/oauth2/v2.0/token') {
    const form = new URLSearchParams(init.body);
    if (form.get('grant_type') === 'authorization_code' && ['local-ms-insufficient', 'local-ms-valid'].includes(form.get('code'))) {
      exchanges++;
      const scope = form.get('code') === 'local-ms-valid' ? 'Mail.ReadWrite Mail.Send User.Read' : 'Mail.ReadWrite User.Read';
      return Response.json({ access_token: 'local-access', refresh_token: 'local-refresh', scope });
    }
    if (form.get('grant_type') === 'refresh_token') {
      if (form.get('refresh_token') !== 'local-refresh') throw new Error('Unexpected Microsoft refresh credential.');
      refreshes++;
      refreshStarted = true;
      await Promise.race([
        new Promise(resolve => { releaseRefresh = resolve; }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Local refresh gate timed out.')), 12000)),
      ]);
      return Response.json({ access_token: 'local-access', refresh_token: 'local-next-refresh', scope: 'Mail.ReadWrite User.Read' });
    }
  }
  if (String(url) === 'https://oauth2.googleapis.com/token') {
    const form = new URLSearchParams(init.body);
    if (form.get('grant_type') === 'refresh_token') {
      refreshes++;
      const expectedRefresh = gatePath === '/installation/mail-refresh-ack' && refreshes > 1 ? 'local-next-refresh' : 'local-refresh';
      if (form.get('refresh_token') !== expectedRefresh) throw new Error('Unexpected local provider refresh credential.');
      refreshStarted = true;
      await Promise.race([
        new Promise(resolve => { releaseRefresh = resolve; }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Local refresh gate timed out.')), 12000)),
      ]);
      if (failRefresh) { failRefresh = false; return new Response('local simulated failure', { status: 400 }); }
      const scope = partialRefresh ? 'openid profile' : 'https://www.googleapis.com/auth/gmail.modify';
      partialRefresh = false;
      return Response.json({ access_token: 'local-access', refresh_token: 'local-next-refresh', scope });
    }
    if (form.get('grant_type') === 'authorization_code') {
      exchanges++;
      if (form.get('code') === 'local-suspended-exchange') {
        exchangeStarted = true;
        await Promise.race([
          new Promise(resolve => { releaseExchange = resolve; }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Local exchange gate timed out.')), 12000)),
        ]);
      }
      const scope = form.get('code') === 'local-insufficient' ? 'openid profile' : 'openid https://www.googleapis.com/auth/gmail.modify';
      return Response.json({ access_token: 'local-access', refresh_token: 'local-refresh', scope });
    }
  }
  if (String(url) === 'https://openidconnect.googleapis.com/v1/userinfo')
    return Response.json({ sub: `local-test-account-${++account}` });
  if (String(url) === 'https://graph.microsoft.com/v1.0/me?$select=id')
    return Response.json({ id: `local-test-account-${++account}` });
  throw new Error('Unexpected outbound request in local test.');
};

export default {
  async fetch(request, env, context) {
    const path = new URL(request.url).pathname;
    if (path === '/__test_ack_arm' && request.method === 'POST') {
      const body = await request.json();
      if (!/^[A-Za-z0-9_-]{43}$/.test(body?.flowId ?? '') || !['activation', 'refresh'].includes(body?.kind ?? 'activation'))
        return new Response(null, { status: 400 });
      if (releaseAck || releaseRefresh) return new Response(null, { status: 409 });
      gateFlowId = body.flowId;
      gatePath = body.kind === 'refresh' ? '/installation/mail-refresh-ack' : '/installation/mail-ack';
      gateAck = true;
      ackCommitted = false;
      acknowledgements = 0;
      disconnections = 0;
      refreshes = 0;
      refreshStarted = false;
      failRefresh = false;
      return new Response(null, { status: 204 });
    }
    if (path === '/__test_ack_status') return Response.json({ ackCommitted, acknowledgements, disconnections, refreshes });
    if (path === '/__test_ack_release' && request.method === 'POST') {
      if (!releaseAck) return new Response(null, { status: 409 });
      releaseAck();
      releaseAck = undefined;
      return new Response(null, { status: 204 });
    }
    if (path === '/__test_refresh_started')
      return Response.json({ refreshStarted });
    if (path === '/__test_exchange_started') return Response.json({ exchangeStarted });
    if (path === '/__test_exchange_release' && request.method === 'POST') {
      if (!releaseExchange) return new Response(null, { status: 409 });
      releaseExchange();
      releaseExchange = undefined;
      return new Response(null, { status: 204 });
    }
    if (path === '/__test_refresh_rearm' && request.method === 'POST') {
      if (releaseRefresh) return new Response(null, { status: 409 });
      refreshStarted = false;
      failRefresh = true;
      return new Response(null, { status: 204 });
    }
    if (path === '/__test_partial_refresh' && request.method === 'POST') {
      if (releaseRefresh) return new Response(null, { status: 409 });
      refreshStarted = false;
      partialRefresh = true;
      return new Response(null, { status: 204 });
    }
    if (path === '/__test_provider_stats')
      return Response.json({ exchanges, refreshes });
    if (path === '/__test_refresh_release' && request.method === 'POST') {
      if (!releaseRefresh) return new Response(null, { status: 409 });
      releaseRefresh();
      releaseRefresh = undefined;
      return new Response(null, { status: 204 });
    }
    const flowId = ['/installation/mail-ack', '/installation/mail-refresh-ack', '/installation/mail-disconnect'].includes(path)
      ? (await request.clone().json()).flowId : undefined;
    const response = await authWorker.fetch(request, env, context);
    if (path === gatePath && flowId === gateFlowId && response.status === 204) acknowledgements++;
    if (path === '/installation/mail-disconnect' && flowId === gateFlowId && response.status === 204) disconnections++;
    if (path === gatePath && flowId === gateFlowId && response.status === 204 && gateAck) {
      gateAck = false;
      ackCommitted = true;
      await Promise.race([
        new Promise(resolve => { releaseAck = resolve; }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Local acknowledgement gate timed out.')), 12000)),
      ]);
    }
    return response;
  },
};
