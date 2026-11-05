// Local test entrypoint only. Production uses worker-entry.js and has no test route.
import authWorker from '../../dist/worker/index.js';
export { DpopState } from '../../dpop-state/src/index.js';
export { InstallationState } from '../../installation-state/src/index.js';

export default {
  async fetch(request, env, context) {
    if (new URL(request.url).pathname !== '/__local_test_object') return authWorker.fetch(request, env, context);
    if (request.headers.get('x-local-test') !== 'local-durable-test') return new Response(null, { status: 403 });
    const input = await request.json();
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.id) || !/^\/[a-z-]+$/.test(input.path)) return new Response(null, { status: 400 });
    const object = env.INSTALLATION_STATE.get(env.INSTALLATION_STATE.idFromName(`installation:v1:${input.id}`));
    return object.fetch(`https://installation.internal${input.path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input.body) });
  },
};
