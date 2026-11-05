import { getExistingBrowserCookie, hashBrowserCookie } from "../_shared/browser-cookie.js";
import { issueFlowReference } from "../_shared/flow-reference.js";
import { readBoundedBody } from "../_shared/installation-proof.js";

const idPattern = /^[A-Za-z0-9_-]{43}$/;
const configurations = {
  "google:mail": { client: "GOOGLE_CLIENT_ID", url: "https://accounts.google.com/o/oauth2/v2/auth", scope: "openid email profile https://www.googleapis.com/auth/gmail.modify", prompt: "consent", accessType: "offline" },
  "google:login": { client: "GOOGLE_LOGIN_CLIENT_ID", url: "https://accounts.google.com/o/oauth2/v2/auth", scope: "openid email profile", prompt: "select_account" },
  "microsoft:mail": { client: "MICROSOFT_CLIENT_ID", url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", scope: "openid profile offline_access Mail.ReadWrite Mail.Send User.Read", prompt: "select_account" },
  "microsoft:login": { client: "MICROSOFT_LOGIN_CLIENT_ID", url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", scope: "openid email profile", prompt: "select_account" },
};

export async function onRequestPost({ request, env }) {
  const headers = { "cache-control": "no-store" };
  if (!env.BROKER_ORIGIN || !env.INSTALLATION_STATE || !env.HANDOFF_LIMIT || !env.AUTH_TICKET_HMAC_KEY)
    return new Response("not configured", { status: 503, headers });
  if (new URL(request.url).origin !== env.BROKER_ORIGIN || request.headers.get("origin") !== env.BROKER_ORIGIN
    || request.headers.get("content-type")?.split(";")[0] !== "application/json") return new Response("rejected", { status: 400, headers });
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 64) return new Response("rejected", { status: 400, headers });
  try {
    if (!(await env.HANDOFF_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  let body;
  try {
    const bytes = await readBoundedBody(request, 1024);
    if (!bytes) throw new Error("oversized");
    body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch { return new Response("rejected", { status: 400, headers }); }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "flowId,id"
    || [body.id, body.flowId].some((value) => typeof value !== "string" || !idPattern.test(value)))
    return new Response("rejected", { status: 400, headers });
  const cookie = getExistingBrowserCookie(request, body.flowId);
  if (!cookie) return new Response("rejected", { status: 400, headers });
  try {
    const objectId = env.INSTALLATION_STATE.idFromName(`installation:v1:${body.id}`);
    const response = await env.INSTALLATION_STATE.get(objectId).fetch("https://installation.internal/start-provider", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ flowId: body.flowId, cookieHash: await hashBrowserCookie(cookie) }),
    });
    if (!response.ok) return new Response("rejected", { status: 409, headers });
    const flow = await response.json();
    const config = configurations[`${flow.provider}:${flow.purpose === "mail" ? "mail" : "login"}`];
    if (!config || !env[config.client]) return new Response("not configured", { status: 503, headers });
    const state = await issueFlowReference(env, env.BROKER_ORIGIN, body.id, body.flowId, flow.state);
    if (!state) return new Response("not configured", { status: 503, headers });
    const provider = new URL(config.url);
    if (flow.microsoftAccountType) provider.pathname = `/${flow.microsoftAccountType}/oauth2/v2.0/authorize`;
    provider.searchParams.set("client_id", env[config.client]);
    provider.searchParams.set("redirect_uri", `${env.BROKER_ORIGIN}/callback`);
    provider.searchParams.set("response_type", "code");
    if (flow.provider === "microsoft") provider.searchParams.set("response_mode", "query");
    provider.searchParams.set("scope", config.scope);
    provider.searchParams.set("state", state);
    provider.searchParams.set("code_challenge", flow.challenge);
    provider.searchParams.set("code_challenge_method", "S256");
    provider.searchParams.set("nonce", flow.nonce);
    provider.searchParams.set("prompt", config.prompt);
    if (config.accessType) provider.searchParams.set("access_type", config.accessType);
    return Response.json({ authorizeUrl: provider.toString() }, { headers });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
}
