import { createLoginExchange } from "../exchange.js";

export const onRequestPost = createLoginExchange({
  clientIdEnv: "MICROSOFT_LOGIN_CLIENT_ID",
  clientSecretEnv: "MICROSOFT_LOGIN_CLIENT_SECRET",
  tokenEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
});
