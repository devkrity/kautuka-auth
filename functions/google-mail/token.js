import { authorizeKeyRevocation, createMailKeyRevocationHandler, createMailTokenHandler, verifyDpop } from "../_shared/mail-token.js";

const handleTokenRequest = createMailTokenHandler({
  providerId: "google-mail",
  providerName: "Google",
  clientIdEnv: "GOOGLE_CLIENT_ID",
  clientSecretEnv: "GOOGLE_CLIENT_SECRET",
  ticketConnector: "kautuka-google-mail",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
  scope: "https://www.googleapis.com/auth/gmail.modify",
});

export const onRequestPost = handleTokenRequest;
export const revokeRegisteredKey = createMailKeyRevocationHandler("google-mail");
export { authorizeKeyRevocation, verifyDpop };
