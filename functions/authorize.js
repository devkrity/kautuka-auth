import { isCanonicalOrigin } from "../public/return-path.js";
import { readTicket } from "./_shared/ticket.js";

const connectors = {
  "kautuka-google-mail": {
    clientEnv: "GOOGLE_CLIENT_ID",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    scope: "https://www.googleapis.com/auth/gmail.modify",
    prompt: "consent",
    accessType: "offline",
  },
  "kautuka-m365-mail": {
    clientEnv: "MICROSOFT_CLIENT_ID",
    authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scope: "offline_access Mail.ReadWrite Mail.Send User.Read",
    prompt: "select_account",
  },
  "kautuka-login-google": {
    clientEnv: "GOOGLE_LOGIN_CLIENT_ID",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    scope: "openid email profile",
    prompt: "select_account",
    requiresNonce: true,
  },
  "kautuka-login-microsoft": {
    clientEnv: "MICROSOFT_LOGIN_CLIENT_ID",
    authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scope: "openid email profile",
    prompt: "select_account",
    requiresNonce: true,
  },
};

export async function onRequestGet(context) {
  const requestUrl = new URL(context.request.url);
  if (requestUrl.protocol !== "https:" || !isCanonicalOrigin(requestUrl.origin)) {
    return text("This sign-in link is not valid.", 400);
  }

  const ticket = await readTicket(context.env, requestUrl.searchParams.get("ticket"), requestUrl.origin);
  if (!ticket) return text("This sign-in link is not valid.", 400);

  const connector = connectors[ticket.connector];
  const clientId = context.env[connector.clientEnv];
  if (!clientId) return text("Sign-in is not configured.", 503);

  const providerUrl = new URL(connector.authorizeUrl);
  if (ticket.microsoftAccountType) {
    providerUrl.pathname = `/${ticket.microsoftAccountType}/oauth2/v2.0/authorize`;
  }
  providerUrl.searchParams.set("client_id", clientId);
  providerUrl.searchParams.set("response_type", "code");
  providerUrl.searchParams.set("redirect_uri", `${requestUrl.origin}/callback`);
  providerUrl.searchParams.set("scope", connector.scope);
  providerUrl.searchParams.set("state", `k1.${requestUrl.searchParams.get("ticket")}`);
  providerUrl.searchParams.set("code_challenge", ticket.challenge);
  providerUrl.searchParams.set("code_challenge_method", "S256");
  providerUrl.searchParams.set("prompt", connector.prompt);
  if (connector.accessType) providerUrl.searchParams.set("access_type", connector.accessType);
  if (connector.requiresNonce) providerUrl.searchParams.set("nonce", ticket.nonce);

  return Response.redirect(providerUrl.toString(), 302);
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
