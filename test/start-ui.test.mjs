import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { isAllowedReturn, returnPathFor } from "../public/return-path.js";

test("start page displays the exact destination and waits for explicit confirmation", async () => {
  const html = await readFile(new URL("../public/start/index.html", import.meta.url), "utf8");
  const inlineScript = html.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(inlineScript, "start page module exists");

  const elements = new Map();
  for (const id of ["status", "confirm", "request-details", "appliance-origin", "request-purpose"]) {
    elements.set(id, {
      textContent: "",
      hidden: id === "request-details",
      disabled: false,
      listeners: {},
      addEventListener(name, handler) { this.listeners[name] = handler; },
    });
  }

  let fetchCount = 0;
  const stored = new Map();
  const location = {
    hash: "#return=https%3A%2F%2Fappliance.example.test%2Flogin%2Fcallback%3Ftenant%3Dvisible-should-reject&connector=kautuka-login-google&state=" + "s".repeat(43) + "&challenge=" + "c".repeat(43) + "&nonce=" + "n".repeat(43),
    origin: "https://broker.example.test",
    replaced: null,
    replace(url) { this.replaced = url; },
  };
  const params = new URLSearchParams(location.hash.slice(1));
  params.set("return", "https://appliance.example.test/login/callback");
  location.hash = `#${params.toString()}`;
  const response = { ok: true, async json() { return { ticket: "signed-ticket" }; } };
  const context = {
    URL, URLSearchParams, location,
    document: { querySelector(selector) { return elements.get(selector.slice(1)); } },
    sessionStorage: { setItem(key, value) { stored.set(key, value); } },
    fetch: async (url, options) => {
      fetchCount++;
      assert.equal(url, "/start/confirm");
      assert.equal(options.method, "POST");
      return response;
    },
    isAllowedReturn,
    returnPathFor,
  };
  const executable = inlineScript.replace(
    /import \{ isAllowedReturn, returnPathFor \} from '\/return-path\.js';/,
    "const { isAllowedReturn, returnPathFor } = globalThis;",
  );
  vm.runInNewContext(executable, context);

  assert.equal(elements.get("appliance-origin").textContent, "https://appliance.example.test");
  assert.equal(elements.get("request-purpose").textContent, "Sign in to Kautuka with Google");
  assert.equal(elements.get("request-details").hidden, false);
  assert.equal(fetchCount, 0, "loading the page must not start confirmation");
  assert.equal(location.replaced, null, "loading the page must not redirect");

  await elements.get("confirm").listeners.click();
  assert.equal(fetchCount, 1, "one click makes exactly one confirmation request");
  assert.equal(stored.get("kautukaAuthTicket"), "signed-ticket");
  assert.match(location.replaced, /^https:\/\/broker\.example\.test\/authorize\?ticket=/);
});
