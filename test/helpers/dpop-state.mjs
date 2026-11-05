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
