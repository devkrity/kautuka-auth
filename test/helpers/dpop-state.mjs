import { DpopStateLogic } from "../../dpop-state/src/state.js";

export class MemoryObjectStorage {
  values = new Map();
  queue = Promise.resolve();
  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, value); }
  async delete(key) { return this.values.delete(key); }
  async list({ prefix = "" } = {}) {
    return new Map([...this.values].filter(([key]) => key.startsWith(prefix)));
  }
  async setAlarm() {}
  transaction(callback) {
    const result = this.queue.then(() => callback(this));
    this.queue = result.catch(() => {});
    return result;
  }
}

export function createStateNamespace() {
  const instances = new Map();
  return {
    idFromName(name) { return name; },
    get(id) {
      if (!instances.has(id)) {
        const storage = new MemoryObjectStorage();
        const object = new DpopStateLogic({ storage });
        instances.set(id, { storage, object });
      }
      const { object } = instances.get(id);
      return {
        async fetch(_url, init) {
          return object.fetch(new Request("https://state.internal", init));
        },
      };
    },
    instances,
  };
}

export async function stateRequest(namespace, provider, jkt, action, fields = {}) {
  const response = await namespace.get(namespace.idFromName(`${provider}:${jkt}`)).fetch("https://state.internal", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action, provider, jkt, ...fields }),
  });
  return { status: response.status, body: await response.json() };
}

