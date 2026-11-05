import { createMailRemovalHandler } from "../_shared/mail-removal.js";
export const onRequestPost = createMailRemovalHandler(false);
