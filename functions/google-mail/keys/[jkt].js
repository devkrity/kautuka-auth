import { revokeRegisteredKey } from "../token.js";

export async function onRequestDelete(context) {
  return revokeRegisteredKey(context.env, context.request, context.params.jkt);
}
