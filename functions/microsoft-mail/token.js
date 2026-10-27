import { createMailKeyRevocationHandler, createMailTokenHandler } from "../_shared/mail-token.js";

const handleTokenRequest = createMailTokenHandler({
  providerId: "microsoft-mail",
  providerName: "Microsoft",
  clientIdEnv: "MICROSOFT_CLIENT_ID",
  clientSecretEnv: "MICROSOFT_CLIENT_SECRET",
  ticketConnector: "kautuka-m365-mail",
  tokenEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  scope: "offline_access Mail.ReadWrite Mail.Send User.Read",
});

export const onRequestPost = handleTokenRequest;
export const revokeRegisteredKey = createMailKeyRevocationHandler("microsoft-mail");
