import { isAllowedGatewayOrigin } from "../../public/return-path.js";

// One durable object owns all connection records for one installation.
// Callers must authenticate the installation and verify provider identity first.
const providers = new Set(["google", "microsoft"]);
const safeId = /^[A-Za-z0-9_-]{43}$/;
const maxAccounts = 5;
const maxConnections = 100;
const maxFlows = 100;
// Mail also needs a provider identity lookup after the token exchange.
// Never re-exchange a code after a worker dies or its result is unknown.
const exchangeLeaseMs = 30_000;
const mailExchangeLeaseMs = 60_000;

export class InstallationStateLogic {
  constructor(state, options = {}) {
    this.storage = state.storage;
    this.newAccountLimit = boundedInteger(options.newAccountLimit, 20, 1, 1000);
    this.newAccountWindowMs = boundedInteger(options.newAccountWindowSeconds, 2592000, 60, 31536000) * 1000;
  }

  async register(thumbprint, jti, expiresAt, now = Date.now()) {
    return (await this.registerStatus(thumbprint, jti, expiresAt, now)) === "ok";
  }

  async registerStatus(thumbprint, jti, expiresAt, now = Date.now()) {
    if (!validProof(thumbprint, jti, expiresAt, now)) return "invalid";
    return this.storage.transaction(async (tx) => {
      const identity = await tx.get("identity");
      if (identity && identity.thumbprint !== thumbprint) return "invalid";
      if (!await consumeProofInTransaction(tx, jti, expiresAt, now)) return "invalid";
      if (identity?.revoked) return "suspended";
      if (!identity) await tx.put("identity", { thumbprint, revoked: false });
      return "ok";
    });
  }

  async authorize(thumbprint, jti, expiresAt, now = Date.now()) {
    return (await this.authorizeStatus(thumbprint, jti, expiresAt, now)) === "ok";
  }

  async authorizeStatus(thumbprint, jti, expiresAt, now = Date.now()) {
    if (!validProof(thumbprint, jti, expiresAt, now)) return "invalid";
    return this.storage.transaction(async (tx) => {
      const identity = await tx.get("identity");
      if (!identity || identity.thumbprint !== thumbprint || !await consumeProofInTransaction(tx, jti, expiresAt, now)) return "invalid";
      return identity.revoked ? "suspended" : "ok";
    });
  }

  async isSuspendedForThumbprint(thumbprint) {
    if (!isId(thumbprint)) return false;
    const identity = await this.storage.get("identity");
    return Boolean(identity?.revoked && identity.thumbprint === thumbprint);
  }

  // Both keys prove possession over the same request body. The receipt makes
  // a response lost after commit retryable without re-enabling the old key.
  async rotate(oldProof, newProof, operationId, now = Date.now()) {
    if (!isId(operationId) || !oldProof || !newProof || oldProof.thumbprint === newProof.thumbprint
      || oldProof.jti === newProof.jti
      || !validProof(oldProof.thumbprint, oldProof.jti, oldProof.expiresAt, now)
      || !validProof(newProof.thumbprint, newProof.jti, newProof.expiresAt, now)) return false;
    return this.storage.transaction(async tx => {
      const identity = await tx.get("identity");
      if (!identity || identity.revoked) return false;
      const receipt = await tx.get("lastRotation");
      const retry = identity.thumbprint === newProof.thumbprint && receipt?.operationId === operationId
        && receipt.oldThumbprint === oldProof.thumbprint && receipt.newThumbprint === newProof.thumbprint;
      if (receipt?.operationId === operationId && !retry) return false;
      if (!retry && identity.thumbprint !== oldProof.thumbprint) return false;
      if (!await consumeProofInTransaction(tx, oldProof.jti, oldProof.expiresAt, now)
        || !await consumeProofInTransaction(tx, newProof.jti, newProof.expiresAt, now)) return false;
      if (!retry) {
        await tx.put("identity", { ...identity, thumbprint: newProof.thumbprint });
        await tx.put("lastRotation", { operationId, oldThumbprint: oldProof.thumbprint, newThumbprint: newProof.thumbprint });
      }
      return true;
    });
  }

  async revoke() {
    return this.storage.transaction(async (tx) => {
      const identity = await tx.get("identity");
      if (!identity || identity.revoked) return false;
      await tx.put("identity", { ...identity, revoked: true });
      return true;
    });
  }

  // Monotonic operator action: retain the identity and connection history as a
  // tombstone. Retrying a lost response must not re-enable or alter it.
  async operatorSuspend(operationId, reason, operatorId, now = Date.now()) {
    if (!isId(operationId) || !/^[a-z0-9_-]{1,64}$/.test(reason ?? "")
      || !/^[a-zA-Z0-9_.-]{1,64}$/.test(operatorId ?? "")) return "invalid";
    return this.storage.transaction(async (tx) => {
      const identity = await tx.get("identity");
      if (!identity) return "not_found";
      if (identity.revoked) return "already_suspended";
      await tx.put("identity", { ...identity, revoked: true, suspension: { operationId, reason, operatorId, at: now } });
      return "suspended";
    });
  }

  async consumeProof(jti, expiresAt, now = Date.now()) {
    if (typeof jti !== "string" || !safeId.test(jti) || !Number.isSafeInteger(expiresAt)
      || expiresAt <= now || expiresAt > now + 120_000) return false;
    return this.storage.transaction((tx) => consumeProofInTransaction(tx, jti, expiresAt, now));
  }

  async consumeDpopProof(fingerprint, now = Date.now()) {
    if (!isId(fingerprint)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const proofs = await tx.list({ prefix: "dpop:" });
      let live = 0;
      for (const [key, expiry] of proofs) {
        if (expiry <= now) await tx.delete(key); else live++;
      }
      if (live >= 4096 || await tx.get(`dpop:${fingerprint}`)) return false;
      await tx.put(`dpop:${fingerprint}`, now + 600_000);
      return true;
    });
  }

  // Nonces are bound to this installation object and a mailbox key. Reuse a
  // live nonce for concurrent calls; each signed proof is still single-use.
  async authenticateMail(thumbprint, jti, expiresAt, jkt, nonce, fingerprint, now = Date.now()) {
    if (!validProof(thumbprint, jti, expiresAt, now) || !isId(jkt) || !isId(fingerprint)) return { status: "invalid" };
    return this.storage.transaction(async (tx) => {
      const identity = await tx.get("identity");
      if (!identity || identity.thumbprint !== thumbprint
        || !await consumeProofInTransaction(tx, jti, expiresAt, now)) return { status: "invalid" };
      if (identity.revoked) return { status: "suspended" };
      const nonces = await tx.list({ prefix: "mail-nonce:" });
      let live = 0;
      for (const [key, record] of nonces) {
        if (record.expiresAt <= now) await tx.delete(key); else live++;
      }
      const key = `mail-nonce:${jkt}`;
      let current = await tx.get(key);
      if (!current || current.expiresAt <= now) {
        if (live >= 256) return { status: "unavailable" };
        current = { value: randomId(), expiresAt: now + 300_000 };
        await tx.put(key, current);
      }
      if (nonce !== current.value) return { status: "challenge", nonce: current.value };
      const proofs = await tx.list({ prefix: "dpop:" });
      let proofCount = 0;
      for (const [proofKey, expiry] of proofs) {
        if (expiry <= now) await tx.delete(proofKey); else proofCount++;
      }
      if (proofCount >= 4096 || await tx.get(`dpop:${fingerprint}`)) return { status: "invalid" };
      await tx.put(`dpop:${fingerprint}`, now + 600_000);
      return { status: "ok" };
    });
  }

  // The server generates flow IDs; caller-supplied IDs are never accepted here.
  async createAuthFlow(input, now = Date.now()) {
    if (!input || !providers.has(input.provider) || !["login", "link", "mail"].includes(input.purpose)
      || typeof input.state !== "string" || !safeId.test(input.state)
      || typeof input.challenge !== "string" || !safeId.test(input.challenge)
      || typeof input.nonce !== "string" || !safeId.test(input.nonce)
      || input.microsoftAccountType != null && (input.provider !== "microsoft" || input.purpose === "mail"
        || !["organizations", "consumers"].includes(input.microsoftAccountType))
      || input.purpose === "mail" && (!isId(input.connectionId) || !isId(input.dpopJkt)
        || !Number.isSafeInteger(input.expectedGeneration) || input.expectedGeneration < 0)
      || !validOrigin(input.gatewayOrigin)) return null;
    const flowId = randomId();
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flows = await tx.list({ prefix: "authflow:" });
      let count = 0;
      for (const [key, flow] of flows) {
        if (flow.expiresAt <= now) {
          await tx.delete(key);
          await tx.delete(`flow:${key.slice("authflow:".length)}`);
        } else {
          count++;
          if (flow.state === input.state) {
            const same = flow.provider === input.provider && flow.purpose === input.purpose
              && flow.challenge === input.challenge && flow.nonce === input.nonce
              && flow.gatewayOrigin === input.gatewayOrigin && flow.connectionId === (input.connectionId ?? null)
              && flow.microsoftAccountType === (input.microsoftAccountType ?? null)
              && flow.dpopJkt === (input.dpopJkt ?? null) && flow.expectedGeneration === (input.expectedGeneration ?? null);
            return same ? key.slice("authflow:".length) : null;
          }
        }
      }
      if (count >= maxFlows || await tx.get(`authflow:${flowId}`)) return null;
      if (input.purpose === "mail") {
        const current = await tx.get(`connection:${input.provider}:${input.connectionId}`);
        if ((current?.generation ?? 0) !== input.expectedGeneration) return null;
      }
      await tx.put(`authflow:${flowId}`, { provider: input.provider, purpose: input.purpose,
        state: input.state, challenge: input.challenge, nonce: input.nonce,
        gatewayOrigin: input.gatewayOrigin, microsoftAccountType: input.microsoftAccountType ?? null, connectionId: input.connectionId ?? null,
        dpopJkt: input.dpopJkt ?? null, expectedGeneration: input.expectedGeneration ?? null,
        expiresAt: now + 300_000, phase: "awaiting_browser", candidates: [] });
      if (input.purpose === "mail") {
        await tx.put(`flow:${flowId}`, { provider: input.provider, connection: input.connectionId,
          dpopJkt: input.dpopJkt, expectedGeneration: input.expectedGeneration, expiresAt: now + 300_000, phase: "pending" });
      }
      return flowId;
    });
  }

  async browserCandidate(flowId, cookieHash, now = Date.now()) {
    if (!isId(flowId) || !isId(cookieHash)) return null;
    const nonce = randomId();
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.phase !== "awaiting_browser") return null;
      const candidates = flow.candidates.filter((item) => item.expiresAt > now);
      const existing = candidates.find((item) => item.cookieHash === cookieHash);
      if (existing) return { nonce: existing.nonce, gatewayOrigin: flow.gatewayOrigin, provider: flow.provider, purpose: flow.purpose };
      if (candidates.length >= 8) return null;
      await tx.put(`authflow:${flowId}`, { ...flow, candidates: [...candidates, { nonce, cookieHash, expiresAt: now + 60_000 }] });
      return { nonce, gatewayOrigin: flow.gatewayOrigin, provider: flow.provider, purpose: flow.purpose };
    });
  }

  async bindBrowser(flowId, nonce, now = Date.now()) {
    if (!isId(flowId) || !isId(nonce)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now) return false;
      if (flow.phase === "browser_bound") return flow.bindingNonce === nonce;
      if (flow.phase !== "awaiting_browser") return false;
      const candidate = flow.candidates.find((item) => item.nonce === nonce && item.expiresAt > now);
      if (!candidate) return false;
      const { candidates: _candidates, ...rest } = flow;
      await tx.put(`authflow:${flowId}`, { ...rest, phase: "browser_bound", browserHash: candidate.cookieHash, bindingNonce: nonce });
      return true;
    });
  }

  async recordCallback(flowId, cookieHash, providerState, result, now = Date.now()) {
    if (!isId(flowId) || !isId(cookieHash) || !isId(providerState)
      || !result || typeof result !== "object" || Array.isArray(result)
      || Object.keys(result).length !== 1
      || !(typeof result.code === "string" && result.code.length > 0 && result.code.length <= 2048
        || typeof result.error === "string" && /^[a-z_]{1,80}$/.test(result.error))) return false;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(result)));
    const fingerprint = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.browserHash !== cookieHash || flow.state !== providerState) return false;
      if (["callback_received", "exchange_in_progress", "exchange_unknown", "result_ready"].includes(flow.phase))
        return flow.callbackFingerprint === fingerprint;
      if (flow.phase !== "authorizing") return false;
      await tx.put(`authflow:${flowId}`, { ...flow, phase: "callback_received", result, callbackFingerprint: fingerprint });
      return true;
    });
  }

  async startProvider(flowId, cookieHash, now = Date.now()) {
    if (!isId(flowId) || !isId(cookieHash)) return null;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.browserHash !== cookieHash
        || !["browser_bound", "authorizing"].includes(flow.phase)) return null;
      if (flow.phase === "browser_bound") await tx.put(`authflow:${flowId}`, { ...flow, phase: "authorizing" });
      return { provider: flow.provider, purpose: flow.purpose, state: flow.state, challenge: flow.challenge,
        nonce: flow.nonce, microsoftAccountType: flow.microsoftAccountType };
    });
  }

  async browserStatus(flowId, cookieHash, now = Date.now()) {
    if (!isId(flowId) || !isId(cookieHash)) return "invalid";
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return "invalid";
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now) return "invalid";
      if (flow.phase === "awaiting_browser") return "waiting";
      if (flow.browserHash !== cookieHash) return "invalid";
      return flow.phase === "browser_bound" ? "ready" : "invalid";
    });
  }

  // Invoked only by the authenticated installation. Once started, an unknown
  // provider outcome must never cause an automatic second code exchange.
  async beginExchange(flowId, verifier, dpopJkt, now = Date.now(), allowedProviders = null) {
    if (!isId(flowId) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return null;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.phase !== "callback_received"
        || !flow.result?.code || flow.challenge !== challenge
        || allowedProviders !== null && (!Array.isArray(allowedProviders) || !allowedProviders.includes(flow.provider))
        || flow.purpose !== "mail" && dpopJkt != null
        || flow.purpose === "mail" && (!isId(dpopJkt) || dpopJkt !== flow.dpopJkt)) return null;
      await tx.put(`authflow:${flowId}`, { ...flow, phase: "exchange_in_progress",
        exchangeDeadline: now + (flow.purpose === "mail" ? mailExchangeLeaseMs : exchangeLeaseMs), result: null, receivedCode: true });
      return { provider: flow.provider, purpose: flow.purpose, nonce: flow.nonce, code: flow.result.code };
    });
  }

  async finishSocialExchange(flowId, sealedResult, now = Date.now()) {
    if (!isId(flowId) || typeof sealedResult !== "string" || sealedResult.length < 20 || sealedResult.length > 40000) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.phase !== "exchange_in_progress" || flow.purpose === "mail"
        || !Number.isSafeInteger(flow.exchangeDeadline) || flow.exchangeDeadline <= now) return false;
      await tx.put(`authflow:${flowId}`, { ...flow, phase: "result_ready", sealedResult });
      return true;
    });
  }

  async readSocialExchange(flowId, verifier, now = Date.now()) {
    if (!isId(flowId) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return null;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.purpose === "mail" || flow.challenge !== challenge || flow.phase !== "result_ready") return null;
      return flow.sealedResult;
    });
  }

  async socialExchangeStatus(flowId, verifier, now = Date.now()) {
    if (!isId(flowId) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return "invalid";
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return "invalid";
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.purpose === "mail" || flow.challenge !== challenge) return "invalid";
      if (flow.phase === "exchange_in_progress" && (!Number.isSafeInteger(flow.exchangeDeadline) || flow.exchangeDeadline <= now)) {
        await tx.put(`authflow:${flowId}`, { ...flow, phase: "exchange_unknown", result: null });
        return "failed";
      }
      if (flow.phase === "exchange_unknown" || flow.phase === "callback_received" && flow.result?.error) return "failed";
      if (["awaiting_browser", "browser_bound", "authorizing", "exchange_in_progress"].includes(flow.phase)) return "pending";
      return "invalid";
    });
  }

  async failExchange(flowId, now = Date.now()) {
    if (!isId(flowId)) return false;
    return this.storage.transaction(async (tx) => {
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.phase !== "exchange_in_progress") return false;
      await tx.put(`authflow:${flowId}`, { ...flow, phase: "exchange_unknown", result: null });
      return true;
    });
  }

  async failExchangeScope(flowId, now = Date.now()) {
    if (!isId(flowId)) return false;
    return this.storage.transaction(async (tx) => {
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.purpose !== "mail" || flow.phase !== "exchange_in_progress") return false;
      await tx.put(`authflow:${flowId}`, { ...flow, phase: "exchange_insufficient_scope", result: null });
      return true;
    });
  }

  // Only invoke after provider identity has been independently validated.
  async verifyFlow(flowId, account, now = Date.now()) {
    if (typeof flowId !== "string" || !safeId.test(flowId) || typeof account !== "string" || !safeId.test(account)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`flow:${flowId}`);
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.phase !== "pending"
        || !authorization || authorization.expiresAt <= now || authorization.phase !== "exchange_in_progress"
        || !Number.isSafeInteger(authorization.exchangeDeadline) || authorization.exchangeDeadline <= now
        || authorization.receivedCode !== true
        || authorization.purpose !== "mail" || authorization.provider !== flow.provider
        || authorization.connectionId !== flow.connection || authorization.dpopJkt !== flow.dpopJkt
        || authorization.expectedGeneration !== flow.expectedGeneration) return false;
      await tx.put(`flow:${flowId}`, { ...flow, account, phase: "verified" });
      return true;
    });
  }

  async cancelFlow(flowId, now = Date.now()) {
    if (typeof flowId !== "string" || !safeId.test(flowId)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`flow:${flowId}`);
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!authorization || authorization.expiresAt <= now || flow?.phase === "acknowledged") return false;
      await tx.delete(`flow:${flowId}`);
      await tx.delete(`authflow:${flowId}`);
      return true;
    });
  }

  async cancelMailFlow(flowId, dpopJkt) {
    if (!isId(flowId) || !isId(dpopJkt)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`flow:${flowId}`);
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!flow && !authorization) {
        for (const active of (await tx.list({ prefix: "connection:" })).values())
          if (active.activationFlowId === flowId) return false;
        return true; // Already removed or expired and not activated.
      }
      if (!flow && authorization?.phase === "admission_denied" && authorization.dpopJkt === dpopJkt) {
        await tx.delete(`authflow:${flowId}`);
        return true;
      }
      if (!flow || !authorization || authorization.purpose !== "mail" || flow.dpopJkt !== dpopJkt
        || authorization.dpopJkt !== dpopJkt || flow.phase === "acknowledged") return false;
      await tx.delete(`flow:${flowId}`);
      await tx.delete(`authflow:${flowId}`);
      return true;
    });
  }

  async disconnectMail(provider, connection, generation, flowId, dpopJkt, now = Date.now()) {
    if (!providers.has(provider) || ![connection, flowId, dpopJkt].every(isId)
      || !Number.isSafeInteger(generation) || generation < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const tombstoneKey = `disconnect:${provider}:${connection}:${generation}`;
      const tombstone = await tx.get(tombstoneKey);
      if (tombstone && tombstone.expiresAt > now) return tombstone.flowId === flowId && tombstone.dpopJkt === dpopJkt;
      const key = `connection:${provider}:${connection}`;
      const active = await tx.get(key);
      if (!active || active.generation !== generation || active.activationFlowId !== flowId || active.dpopJkt !== dpopJkt) return false;
      const tombstones = await tx.list({ prefix: "disconnect:" });
      let live = 0;
      let oldestKey = null;
      let oldestExpiry = Number.POSITIVE_INFINITY;
      for (const [entry, record] of tombstones) {
        if (record.expiresAt <= now) await tx.delete(entry);
        else {
          live++;
          if (record.expiresAt < oldestExpiry) { oldestKey = entry; oldestExpiry = record.expiresAt; }
        }
      }
      if (live >= 4096 && oldestKey) await tx.delete(oldestKey);
      for (const [entry, flow] of await tx.list({ prefix: "flow:" })) {
        if (flow.provider === provider && flow.connection === connection) await tx.delete(entry);
      }
      for (const [entry, flow] of await tx.list({ prefix: "authflow:" })) {
        if (flow.provider === provider && flow.connectionId === connection) await tx.delete(entry);
      }
      await tx.delete(key);
      await tx.put(tombstoneKey, { flowId, dpopJkt, expiresAt: now + 86_400_000 });
      return true;
    });
  }

  async sweepExpired(now = Date.now()) {
    return this.storage.transaction(async (tx) => {
      for (const [key, flow] of await tx.list({ prefix: "flow:" })) {
        if (flow.expiresAt <= now) await tx.delete(key);
      }
      for (const [key, flow] of await tx.list({ prefix: "authflow:" })) {
        if (flow.expiresAt <= now) await tx.delete(key);
      }
      for (const [key, expiry] of await tx.list({ prefix: "proof:" })) {
        if (expiry <= now) await tx.delete(key);
      }
      for (const [key, expiry] of await tx.list({ prefix: "dpop:" })) {
        if (expiry <= now) await tx.delete(key);
      }
      for (const [key, record] of await tx.list({ prefix: "mail-nonce:" })) {
        if (record.expiresAt <= now) await tx.delete(key);
      }
      for (const [key, record] of await tx.list({ prefix: "disconnect:" })) {
        if (record.expiresAt <= now) await tx.delete(key);
      }
    });
  }

  // Reserve capacity and store the result together. Activation happens only
  // after the Gateway has durably stored its copy and acknowledges the flow.
  async finishMailExchange(flowId, sealedResult, now = Date.now(), credentialHash = null, credentialEnvelope = null) {
    if (!isId(flowId) || !isId(credentialHash) || !await matchesEnvelope(credentialEnvelope, credentialHash)
      || typeof sealedResult !== "string" || sealedResult.length < 20 || sealedResult.length > 60000)
      return { ok: false, reason: "invalid" };
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return { ok: false, reason: "revoked" };
      const flow = await tx.get(`flow:${flowId}`);
      if (!flow || flow.expiresAt <= now) return { ok: false, reason: "stale" };
      const { provider, account, connection, expectedGeneration } = flow;
      if (["provisional", "acknowledged"].includes(flow.phase)) {
        const active = await tx.get(`connection:${provider}:${connection}`);
        const expected = flow.phase === "provisional" ? expectedGeneration : flow.generation;
        return (active?.generation ?? 0) === expected && flow.sealedResult === sealedResult && flow.credentialHash === credentialHash
          ? { ok: true, generation: flow.generation }
          : { ok: false, reason: "stale" };
      }
      if (flow.phase !== "verified" || !valid(provider, account, connection)) return { ok: false, reason: "stale" };
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!authorization || authorization.phase !== "exchange_in_progress" || authorization.expiresAt <= now
        || !Number.isSafeInteger(authorization.exchangeDeadline) || authorization.exchangeDeadline <= now)
        return { ok: false, reason: "stale" };
      const connections = await tx.list({ prefix: `connection:${provider}:` });
      const activeAccounts = new Set();
      for (const item of connections.values()) activeAccounts.add(item.account);
      const occupiedConnections = new Set(connections.keys());
      for (const candidate of (await tx.list({ prefix: "flow:" })).values()) {
        if (candidate.phase !== "provisional" || candidate.provider !== provider || candidate.expiresAt <= now) continue;
        if (candidate.connection === connection) return { ok: false, reason: "connection_in_use" };
        activeAccounts.add(candidate.account);
        occupiedConnections.add(`connection:${provider}:${candidate.connection}`);
      }
      const key = `connection:${provider}:${connection}`;
      const prior = await tx.get(key);
      if ((prior?.generation ?? 0) !== expectedGeneration) return { ok: false, reason: "stale" };
      if (prior && prior.account !== account) return { ok: false, reason: "connection_in_use" };
      if (!occupiedConnections.has(key) && occupiedConnections.size >= maxConnections) return { ok: false, reason: "capacity" };
      if (!activeAccounts.has(account) && activeAccounts.size >= maxAccounts) {
        await tx.put(`authflow:${flowId}`, { ...authorization, phase: "admission_denied", result: null, admissionReason: "limit" });
        await tx.delete(`flow:${flowId}`);
        return { ok: false, reason: "limit" };
      }
      // Keep a bounded, installation-scoped history independent of active
      // connections, so repeated disconnects cannot reset the rolling budget.
      const historyKey = `account-history:${provider}`;
      const history = (await tx.get(historyKey) ?? []).filter(entry => entry.at + this.newAccountWindowMs > now);
      if (!activeAccounts.has(account) && !history.some(entry => entry.account === account)) {
        if (history.length >= this.newAccountLimit) {
          const retryAt = Math.min(...history.map(entry => entry.at + this.newAccountWindowMs));
          await tx.put(`authflow:${flowId}`, { ...authorization, phase: "admission_denied", result: null, admissionReason: "new_account_limit", retryAt });
          await tx.delete(`flow:${flowId}`);
          return { ok: false, reason: "new_account_limit", retryAt };
        }
        history.push({ account, at: now });
      }
      await tx.put(historyKey, history);
      const generation = (await tx.get("nextGeneration") ?? 0) + 1;
      if (!Number.isSafeInteger(generation)) return { ok: false, reason: "capacity" };
      await tx.put("nextGeneration", generation);
      await tx.put(`flow:${flowId}`, { ...flow, phase: "provisional", generation, sealedResult, credentialHash, credentialEnvelope });
      return { ok: true, generation };
    });
  }

  async readMailExchange(flowId, verifier, dpopJkt, now = Date.now()) {
    if (!isId(flowId) || !isId(dpopJkt) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return null;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const flow = await tx.get(`flow:${flowId}`);
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || !["provisional", "acknowledged"].includes(flow.phase) || flow.dpopJkt !== dpopJkt
        || !flow.sealedResult || !authorization || authorization.expiresAt <= now || authorization.challenge !== challenge) return null;
      const active = await tx.get(`connection:${flow.provider}:${flow.connection}`);
      const expected = flow.phase === "provisional" ? flow.expectedGeneration : flow.generation;
      if ((active?.generation ?? 0) !== expected || flow.phase === "acknowledged" && active.dpopJkt !== dpopJkt) return null;
      return { sealedResult: flow.sealedResult, generation: flow.generation };
    });
  }

  async mailExchangeStatus(flowId, verifier, dpopJkt, now = Date.now()) {
    if (!isId(flowId) || !isId(dpopJkt) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return "invalid";
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return "invalid";
      const flow = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || flow.purpose !== "mail" || flow.challenge !== challenge || flow.dpopJkt !== dpopJkt) return "invalid";
      if (flow.phase === "exchange_insufficient_scope") return { reason: "insufficient_scope" };
      if (flow.phase === "admission_denied") return { reason: flow.admissionReason, retryAt: flow.retryAt };
      if (flow.phase === "exchange_in_progress" && (!Number.isSafeInteger(flow.exchangeDeadline) || flow.exchangeDeadline <= now)) {
        await tx.put(`authflow:${flowId}`, { ...flow, phase: "exchange_unknown", result: null });
        return "failed";
      }
      if (flow.phase === "exchange_unknown" || flow.phase === "callback_received" && flow.result?.error) return "failed";
      if (["awaiting_browser", "browser_bound", "authorizing", "exchange_in_progress"].includes(flow.phase)) return "pending";
      return "invalid";
    });
  }

  async acknowledgeMailExchange(flowId, verifier, dpopJkt, now = Date.now()) {
    if (!isId(flowId) || !isId(dpopJkt) || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const flow = await tx.get(`flow:${flowId}`);
      const authorization = await tx.get(`authflow:${flowId}`);
      if (!flow || flow.expiresAt <= now || !["provisional", "acknowledged"].includes(flow.phase)
        || flow.dpopJkt !== dpopJkt || !authorization || authorization.expiresAt <= now || authorization.challenge !== challenge) return false;
      const key = `connection:${flow.provider}:${flow.connection}`;
      const active = await tx.get(key);
      if (flow.phase === "acknowledged") return active?.generation === flow.generation && active.dpopJkt === dpopJkt;
      if ((active?.generation ?? 0) !== flow.expectedGeneration) return false;
      await tx.put(key, { account: flow.account, generation: flow.generation, dpopJkt, activationFlowId: flowId,
        credentialHash: flow.credentialHash, credentialEnvelope: flow.credentialEnvelope });
      await tx.put(`flow:${flowId}`, { ...flow, phase: "acknowledged" });
      return true;
    });
  }

  async wasMailActivated(provider, connection, generation, flowId, dpopJkt) {
    if (!providers.has(provider) || !isId(connection) || !isId(flowId) || !isId(dpopJkt)
      || !Number.isSafeInteger(generation) || generation < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const active = await tx.get(`connection:${provider}:${connection}`);
      return Boolean(active && active.generation === generation && active.activationFlowId === flowId && active.dpopJkt === dpopJkt);
    });
  }

  async beginMailRefresh(input, now = Date.now()) {
    if (!input || !providers.has(input.provider) || ![input.connection, input.flowId, input.dpopJkt, input.operationId, input.credentialHash].every(isId)
      || !Number.isSafeInteger(input.generation) || input.generation < 1) return { status: "invalid" };
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return { status: "invalid" };
      const key = `connection:${input.provider}:${input.connection}`;
      const active = await tx.get(key);
      if (!active || active.generation !== input.generation || active.activationFlowId !== input.flowId || active.dpopJkt !== input.dpopJkt)
        return { status: "invalid" };
      const refresh = active.refresh;
      if (refresh?.status === "complete") {
        if (refresh.operationId === input.operationId && refresh.inputHash === input.credentialHash)
          return { status: "complete", sealedResult: refresh.sealedResult };
        return { status: "busy" };
      }
      if (refresh?.status === "unknown") return { status: "unknown" };
      if (refresh?.status === "insufficient_scope") return { status: "insufficient_scope" };
      if (refresh?.status === "pending") {
        if (refresh.deadline <= now) {
          await tx.put(key, { ...active, refresh: { ...refresh, status: "unknown" } });
          return { status: "unknown" };
        }
        return { status: "busy" };
      }
      if (active.credentialHash !== input.credentialHash || active.lastRefreshOperation === input.operationId) return { status: "invalid" };
      await tx.put(key, { ...active, refresh: { status: "pending", operationId: input.operationId,
        inputHash: input.credentialHash, deadline: now + 30_000 } });
      return { status: "claimed" };
    });
  }

  async failMailRefreshScope(input, now = Date.now()) {
    if (!input || !providers.has(input.provider) || ![input.connection, input.flowId, input.dpopJkt, input.operationId, input.credentialHash].every(isId)
      || !Number.isSafeInteger(input.generation) || input.generation < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const key = `connection:${input.provider}:${input.connection}`;
      const active = await tx.get(key), refresh = active?.refresh;
      if (!active || active.generation !== input.generation || active.activationFlowId !== input.flowId || active.dpopJkt !== input.dpopJkt
        || active.credentialHash !== input.credentialHash || refresh?.status !== "pending" || refresh.operationId !== input.operationId
        || refresh.inputHash !== input.credentialHash || refresh.deadline <= now) return false;
      await tx.put(key, { ...active, refresh: { ...refresh, status: "insufficient_scope" } });
      return true;
    });
  }

  async finishMailRefresh(input, now = Date.now()) {
    if (!input || !providers.has(input.provider) || ![input.connection, input.flowId, input.dpopJkt, input.operationId, input.credentialHash, input.nextCredentialHash].every(isId)
      || !Number.isSafeInteger(input.generation) || input.generation < 1 || typeof input.sealedResult !== "string"
      || input.sealedResult.length < 20 || input.sealedResult.length > 60000 || input.nextCredentialHash === input.credentialHash
      || !await matchesEnvelope(input.nextCredentialEnvelope, input.nextCredentialHash)) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const key = `connection:${input.provider}:${input.connection}`;
      const active = await tx.get(key);
      const refresh = active?.refresh;
      if (!active || active.generation !== input.generation || active.activationFlowId !== input.flowId || active.dpopJkt !== input.dpopJkt
        || active.credentialHash !== input.credentialHash || refresh?.status !== "pending" || refresh.operationId !== input.operationId
        || refresh.inputHash !== input.credentialHash || refresh.deadline <= now) return false;
      await tx.put(key, { ...active, credentialHash: input.nextCredentialHash, credentialEnvelope: input.nextCredentialEnvelope,
        refresh: { ...refresh, status: "complete", sealedResult: input.sealedResult } });
      return true;
    });
  }

  async acknowledgeMailRefresh(input) {
    if (!input || !providers.has(input.provider) || ![input.connection, input.flowId, input.dpopJkt, input.operationId].every(isId)
      || !Number.isSafeInteger(input.generation) || input.generation < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const key = `connection:${input.provider}:${input.connection}`;
      const active = await tx.get(key);
      if (!active || active.generation !== input.generation || active.activationFlowId !== input.flowId || active.dpopJkt !== input.dpopJkt) return false;
      if (active.lastRefreshOperation === input.operationId) return true;
      if (active.refresh?.status !== "complete" || active.refresh.operationId !== input.operationId) return false;
      const { refresh: _refresh, ...rest } = active;
      await tx.put(key, { ...rest, lastRefreshOperation: input.operationId });
      return true;
    });
  }

  async readMailRefresh(input) {
    if (!input || !providers.has(input.provider) || ![input.connection, input.flowId, input.dpopJkt, input.operationId, input.credentialHash].every(isId)
      || !Number.isSafeInteger(input.generation) || input.generation < 1) return null;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return null;
      const active = await tx.get(`connection:${input.provider}:${input.connection}`);
      if (!active || active.generation !== input.generation || active.activationFlowId !== input.flowId || active.dpopJkt !== input.dpopJkt
        || active.refresh?.status !== "complete" || active.refresh.operationId !== input.operationId
        || active.refresh.inputHash !== input.credentialHash) return null;
      return active.refresh.sealedResult;
    });
  }

  async disconnect(provider, connection, expectedGeneration) {
    if (!providers.has(provider) || typeof connection !== "string" || !safeId.test(connection)
      || !Number.isSafeInteger(expectedGeneration) || expectedGeneration < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const key = `connection:${provider}:${connection}`;
      const record = await tx.get(key);
      if (!record || record.generation !== expectedGeneration) return false;
      const flows = await tx.list({ prefix: "flow:" });
      for (const [flowKey, flow] of flows) {
        if (flow.provider === provider && flow.connection === connection) await tx.delete(flowKey);
      }
      for (const [flowKey, flow] of await tx.list({ prefix: "authflow:" })) {
        if (flow.provider === provider && flow.connectionId === connection) await tx.delete(flowKey);
      }
      await tx.delete(key);
      return true;
    });
  }

  async isActive(provider, connection, generation) {
    if (!providers.has(provider) || typeof connection !== "string" || !safeId.test(connection)
      || !Number.isSafeInteger(generation) || generation < 1) return false;
    return this.storage.transaction(async (tx) => {
      if (!await isEnabled(tx)) return false;
      const record = await tx.get(`connection:${provider}:${connection}`);
      return Boolean(record && record.generation === generation);
    });
  }
}

async function isEnabled(storage) {
  const identity = await storage.get("identity");
  return Boolean(identity && !identity.revoked);
}

async function consumeProofInTransaction(tx, jti, expiresAt, now) {
  const records = await tx.list({ prefix: "proof:" });
  let live = 0;
  for (const [key, expiry] of records) {
    if (expiry <= now) await tx.delete(key);
    else live++;
  }
  if (await tx.get(`proof:${jti}`) || live >= 4096) return false;
  await tx.put(`proof:${jti}`, expiresAt);
  return true;
}

function validProof(thumbprint, jti, expiresAt, now) {
  return typeof thumbprint === "string" && safeId.test(thumbprint)
    && typeof jti === "string" && safeId.test(jti) && Number.isSafeInteger(expiresAt)
    && expiresAt > now && expiresAt <= now + 120_000;
}

function valid(provider, account, connection) {
  return providers.has(provider) && typeof account === "string" && safeId.test(account)
    && typeof connection === "string" && safeId.test(connection);
}

function isId(value) { return typeof value === "string" && safeId.test(value); }

function boundedInteger(value, fallback, minimum, maximum) {
  if (value === undefined) return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new Error("Invalid mail account rate limit configuration");
  return number;
}

async function matchesEnvelope(envelope, expected) {
  if (typeof envelope !== "string" || !envelope.startsWith("kmf1.") || envelope.length > 60000 || !isId(expected)) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(envelope));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "") === expected;
}

function randomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function validOrigin(value) {
  return isAllowedGatewayOrigin(value);
}
