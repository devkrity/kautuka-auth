export class DpopStateLogic {
  constructor(state) {
    this.state = state;
    this.storage = state.storage;
  }

  async fetch(request) {
    const { action, ...input } = await request.json();
    if (action === "nonce") return Response.json({ nonce: await this.issueNonce() });
    if (action === "consume") return Response.json({ ok: await this.consume(input.nonce, input.jti) });
    if (action === "get") return Response.json({ revoked: Boolean(await this.storage.get("revoked")) });
    if (action === "finalize") return Response.json({ ok: !(await this.storage.get("revoked")) });
    if (action === "revoke") return Response.json({ ok: await this.revoke() });
    return new Response("bad request", { status: 400 });
  }

  async sweepExpired() {
    const now = Date.now();
    for (const prefix of ["nonce:", "jti:"]) {
      const records = await this.storage.list({ prefix });
      for (const [key, expiresAt] of records) {
        if (expiresAt < now) await this.storage.delete(key);
      }
    }
  }

  async issueNonce() {
    await this.sweepExpired();
    const nonces = await this.storage.list({ prefix: "nonce:" });
    if (nonces.size >= 500) return null;

    const nonce = crypto.randomUUID() + crypto.randomUUID();
    await this.storage.put(`nonce:${nonce}`, Date.now() + 300_000);
    await this.state.storage.setAlarm(Date.now() + 300_000);
    return nonce;
  }

  async consume(nonce, jti) {
    if (typeof nonce !== "string" || typeof jti !== "string") return false;
    return this.storage.transaction(async (transaction) => {
      const expiresAt = await transaction.get(`nonce:${nonce}`);
      if (!expiresAt || expiresAt < Date.now() || await transaction.get(`jti:${jti}`)) return false;
      if (await transaction.get("revoked")) return false;

      const proofs = await transaction.list({ prefix: "jti:" });
      if (proofs.size >= 2000) return false;
      await transaction.delete(`nonce:${nonce}`);
      await transaction.put(`jti:${jti}`, Date.now() + 300_000);
      return true;
    });
  }

  async revoke() {
    return this.storage.transaction(async (transaction) => {
      await transaction.put("revoked", true);
      return true;
    });
  }

  async alarm() {
    await this.sweepExpired();
    const records = await this.storage.list();
    if ([...records.values()].some((value) => typeof value === "number" && value > Date.now())) {
      await this.state.storage.setAlarm(Date.now() + 300_000);
    }
  }
}

export default {
  fetch() {
    return new Response("not found", { status: 404 });
  },
};

