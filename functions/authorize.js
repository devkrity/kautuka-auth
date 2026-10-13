const connectors = {
  "kautuka-google-mail": {
    clientEnv: "GOOGLE_CLIENT_ID",
    authorize: "https://accounts.google.com/o/oauth2/v2/auth",
    scope: "https://www.googleapis.com/auth/gmail.modify",
    prompt: "consent",
    accessType: "offline",
  },
  "kautuka-m365-mail": {
    clientEnv: "MICROSOFT_CLIENT_ID",
    authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scope: "offline_access Mail.ReadWrite Mail.Send User.Read",
    prompt: "select_account",
  },
  "kautuka-login-google": {
    clientEnv: "GOOGLE_LOGIN_CLIENT_ID",
    authorize: "https://accounts.google.com/o/oauth2/v2/auth",
    scope: "openid email profile",
    prompt: "select_account",
    requiresNonce: true,
  },
  "kautuka-login-microsoft": {
    clientEnv: "MICROSOFT_LOGIN_CLIENT_ID",
    authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scope: "openid email profile",
    prompt: "select_account",
    requiresNonce: true,
  },
};

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  if (url.protocol !== "https:") {
    return text("This sign-in link is not valid.", 400);
  }

  const connectorId = url.searchParams.get("connector") ?? "";
  const connector = connectors[connectorId];
  const clientId = connector ? context.env[connector.clientEnv] : "";
  const state = url.searchParams.get("state") ?? "";
  const challenge = url.searchParams.get("challenge") ?? "";
  const nonce = url.searchParams.get("nonce") ?? "";
  if (!connector || !clientId || !isPkce(state) || !isPkce(challenge)) {
    return text("This sign-in link is not valid.", 400);
  }

  if (connector.requiresNonce && !isPkce(nonce)) {
    return text("This sign-in link is not valid.", 400);
  }

  const microsoftAccountType = url.searchParams.get("microsoftAccountType");
  if (microsoftAccountType !== null &&
      (connectorId !== "kautuka-login-microsoft" ||
       !["organizations", "consumers"].includes(microsoftAccountType))) {
    return text("This sign-in link is not valid.", 400);
  }

  const target = new URL(connector.authorize);
  if (microsoftAccountType !== null) {
    target.pathname = `/${microsoftAccountType}/oauth2/v2.0/authorize`;
  }
  target.searchParams.set("client_id", clientId);
  target.searchParams.set("response_type", "code");
  target.searchParams.set("redirect_uri", `${url.origin}/callback`);
  target.searchParams.set("scope", connector.scope);
  target.searchParams.set("state", state);
  target.searchParams.set("code_challenge", challenge);
  target.searchParams.set("code_challenge_method", "S256");
  target.searchParams.set("prompt", connector.prompt);
  if (connector.accessType) {
    target.searchParams.set("access_type", connector.accessType);
  }

  if (connector.requiresNonce) {
    target.searchParams.set("nonce", nonce);
  }

  return Response.redirect(target.toString(), 302);
}

function isPkce(value) {
  return /^[A-Za-z0-9_-]{43,128}$/.test(value);
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
