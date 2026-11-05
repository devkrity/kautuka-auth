import { DurableObject } from "cloudflare:workers";
import { InstallationStateLogic } from "./state.js";

// This object is reachable only through the Worker binding, not by external URLs.
export class InstallationState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.logic = new InstallationStateLogic(ctx, { newAccountLimit: env.MAIL_NEW_ACCOUNT_LIMIT, newAccountWindowSeconds: env.MAIL_NEW_ACCOUNT_WINDOW_SECONDS });
  }

  async fetch(request) {
    if (request.method !== "POST") return new Response(null, { status: 404 });
    const path = new URL(request.url).pathname;
    let input;
    try { input = await request.json(); } catch { return new Response(null, { status: 400 }); }
    if (path === "/register") {
      const ok = await this.logic.register(input.thumbprint, input.jti, input.expiresAt);
      if (!ok) return new Response(null, { status: 409 });
      await this.scheduleCleanup();
      return new Response(null, { status: 204 });
    }
    if (path === "/rotate") {
      const ok = await this.logic.rotate(input.oldProof, input.newProof, input.operationId);
      return new Response(null, { status: ok ? 204 : 409 });
    }
    if (path === "/create-flow") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      const flowId = await this.logic.createAuthFlow(input.flow);
      if (!flowId) return new Response(null, { status: 400 });
      await this.scheduleCleanup();
      return Response.json({ flowId });
    }
    if (path === "/browser-candidate") {
      const candidate = await this.logic.browserCandidate(input.flowId, input.cookieHash);
      if (!candidate) return new Response(null, { status: 400 });
      return Response.json(candidate);
    }
    if (path === "/bind-browser") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      return new Response(null, { status: await this.logic.bindBrowser(input.flowId, input.nonce) ? 204 : 409 });
    }
    if (path === "/start-provider") {
      const result = await this.logic.startProvider(input.flowId, input.cookieHash);
      return result ? Response.json(result) : new Response(null, { status: 409 });
    }
    if (path === "/browser-status") {
      return Response.json({ status: await this.logic.browserStatus(input.flowId, input.cookieHash) });
    }
    if (path === "/provider-callback") {
      return new Response(null, { status: await this.logic.recordCallback(input.flowId, input.cookieHash, input.state, input.result) ? 204 : 409 });
    }
    if (path === "/claim-social-exchange") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      const cached = await this.logic.readSocialExchange(input.flowId, input.verifier);
      if (cached) return Response.json({ sealedResult: cached });
      const claim = await this.logic.beginExchange(input.flowId, input.verifier, null);
      if (!claim || claim.purpose === "mail") {
        const status = await this.logic.socialExchangeStatus(input.flowId, input.verifier);
        return new Response(null, { status: status === "pending" ? 202 : status === "failed" ? 410 : 409 });
      }
      return Response.json({ claim });
    }
    if (path === "/finish-social-exchange") {
      return new Response(null, { status: await this.logic.finishSocialExchange(input.flowId, input.sealedResult) ? 204 : 409 });
    }
    if (path === "/claim-mail-exchange") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      await this.scheduleCleanup();
      const cached = await this.logic.readMailExchange(input.flowId, input.verifier, input.dpopJkt);
      if (cached) return Response.json(cached);
      const claim = await this.logic.beginExchange(input.flowId, input.verifier, input.dpopJkt, Date.now(), input.allowedProviders);
      if (claim?.purpose === "mail") return Response.json({ claim });
      const status = await this.logic.mailExchangeStatus(input.flowId, input.verifier, input.dpopJkt);
      if (status?.reason === "insufficient_scope") return Response.json({ code: "insufficient_scope" }, { status: 403 });
      if (typeof status === "object" && status?.reason === "new_account_limit")
        return Response.json({ code: status.reason, retryAt: status.retryAt, restartRequired: true }, { status: 429 });
      if (typeof status === "object" && status?.reason === "limit") return Response.json({ code: "active_account_limit" }, { status: 409 });
      return new Response(null, { status: status === "pending" ? 202 : status === "failed" ? 410 : 409 });
    }
    if (path === "/finish-mail-exchange") {
      if (!await this.logic.verifyFlow(input.flowId, input.account)) return new Response(null, { status: 409 });
      const result = await this.logic.finishMailExchange(input.flowId, input.sealedResult, Date.now(), input.credentialHash, input.credentialEnvelope);
      return result.ok ? Response.json(result) : Response.json({ error: result.reason, retryAt: result.retryAt }, { status: result.reason === "new_account_limit" ? 429 : 409 });
    }
    if (path === "/read-mail-result") {
      const result = await this.logic.readMailExchange(input.flowId, input.verifier, input.dpopJkt);
      return result ? Response.json(result) : new Response(null, { status: 409 });
    }
    if (path === "/ack-mail-exchange") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      await this.scheduleCleanup();
      return new Response(null, { status: await this.logic.acknowledgeMailExchange(input.flowId, input.verifier, input.dpopJkt) ? 204 : 409 });
    }
    if (path === "/mail-status") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      await this.scheduleCleanup();
      const active = await this.logic.wasMailActivated(input.provider, input.connectionId, input.generation, input.flowId, input.dpopJkt);
      return Response.json({ active });
    }
    if (path === "/cancel-mail-flow" || path === "/disconnect-mail") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      const ok = path === "/cancel-mail-flow"
        ? await this.logic.cancelMailFlow(input.flowId, input.dpopJkt)
        : await this.logic.disconnectMail(input.provider, input.connectionId, input.generation, input.flowId, input.dpopJkt);
      await this.scheduleCleanup();
      return new Response(null, { status: ok ? 204 : 409 });
    }
    if (path === "/claim-mail-refresh") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      await this.scheduleCleanup();
      return Response.json(await this.logic.beginMailRefresh(input));
    }
    if (path === "/finish-mail-refresh") {
      return new Response(null, { status: await this.logic.finishMailRefresh(input) ? 204 : 409 });
    }
    if (path === "/fail-mail-refresh-scope") {
      return new Response(null, { status: await this.logic.failMailRefreshScope(input) ? 204 : 409 });
    }
    if (path === "/read-mail-refresh") {
      const sealedResult = await this.logic.readMailRefresh(input);
      return sealedResult ? Response.json({ sealedResult }) : new Response(null, { status: 409 });
    }
    if (path === "/ack-mail-refresh") {
      if (!await this.logic.authorize(input.thumbprint, input.jti, input.expiresAt)) return new Response(null, { status: 403 });
      if (!await this.logic.consumeDpopProof(input.dpopFingerprint)) return new Response(null, { status: 403 });
      await this.scheduleCleanup();
      return new Response(null, { status: await this.logic.acknowledgeMailRefresh(input) ? 204 : 409 });
    }
    if (path === "/fail-exchange") {
      return new Response(null, { status: await this.logic.failExchange(input.flowId) ? 204 : 409 });
    }
    if (path === "/fail-exchange-scope") {
      return new Response(null, { status: await this.logic.failExchangeScope(input.flowId) ? 204 : 409 });
    }
    return new Response(null, { status: 404 });
  }

  async alarm() {
    await this.logic.sweepExpired();
    const records = await this.ctx.storage.list();
    if ([...records].some(([key]) => key.startsWith("proof:") || key.startsWith("dpop:") || key.startsWith("disconnect:") || key.startsWith("flow:") || key.startsWith("authflow:"))) {
      await this.scheduleCleanup();
    }
  }

  async scheduleCleanup() {
    const scheduled = await this.ctx.storage.getAlarm();
    if (scheduled === null) await this.ctx.storage.setAlarm(Date.now() + 120_000);
  }
}
