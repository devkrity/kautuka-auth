import { createLoginExchange } from "../exchange.js";

export const onRequestPost = createLoginExchange({
  clientIdEnv: "GOOGLE_LOGIN_CLIENT_ID",
  clientSecretEnv: "GOOGLE_LOGIN_CLIENT_SECRET",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
});
