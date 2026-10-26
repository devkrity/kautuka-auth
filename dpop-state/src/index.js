import { DurableObject } from "cloudflare:workers";
import { DpopStateLogic } from "./state.js";

export class DpopState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.logic = new DpopStateLogic(ctx);
  }

  fetch(request) {
    return this.logic.fetch(request);
  }

  alarm() {
    return this.logic.alarm();
  }
}

export default {
  fetch() {
    return new Response("not found", { status: 404 });
  },
};
