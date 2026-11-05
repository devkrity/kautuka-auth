import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const html = await readFile(new URL("../public/handoff/index.html", import.meta.url), "utf8");
const callback = await readFile(new URL("../public/callback/index.html", import.meta.url), "utf8");
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1];

async function runHandoff(candidate, status = "ready") {
  const nodes = new Map(["status", "details", "notice", "continue"].map(id => [id, {
    textContent: "", hidden: id === "details" || id === "notice", disabled: id === "continue", listeners: {},
    addEventListener(name, fn) { this.listeners[name] = fn; },
  }]));
  const messages = [], calls = [], redirects = [];
  const opener = { postMessage(message, target) { messages.push({ message, target }); } };
  const location = { hash: `#id=${"a".repeat(43)}&flow=${"c".repeat(43)}`, pathname: "/handoff/", replace(value) { redirects.push(value); } };
  const context = { document: { querySelector(selector) { return nodes.get(selector.slice(1)); } },
    window: { opener }, location, history: { replaceState() {} }, URL, URLSearchParams, AbortSignal, Date, setTimeout,
    fetch: async (path) => { calls.push(path); return { ok: true, async json() {
      return path === "/handoff/candidate" ? candidate : path === "/handoff/status" ? { status } : { authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" };
    } }; },
  };
  await vm.runInNewContext(`(async () => { ${script} })()`, context);
  return { nodes, messages, calls, redirects };
}

test("active handoff binds the exact destination before consent and retains the mail warning", async () => {
  assert.ok(script);
  for (const page of [html, callback]) {
    assert.match(page, /href="\/broker\.css"/);
    assert.match(page, /class="brand"/);
  }
  const candidate = { gatewayOrigin: "http://192.168.1.20:20229", nonce: "b".repeat(43), provider: "microsoft", purpose: "mail" };
  const result = await runHandoff(candidate);
  assert.equal(result.messages.length, 1);
  assert.equal(result.messages[0].target, candidate.gatewayOrigin);
  assert.match(result.nodes.get("details").textContent, /Microsoft.*192\.168\.1\.20/);
  assert.match(result.nodes.get("notice").textContent, /trust the operator/);
  assert.equal(result.nodes.get("continue").disabled, false);
  assert.equal(result.calls.includes("/handoff/authorize"), false);
  await result.nodes.get("continue").listeners.click();
  assert.equal(result.calls.filter(path => path === "/handoff/authorize").length, 1);
  assert.match(result.redirects[0], /^https:\/\/login\.microsoftonline\.com\//);
});

test("rejected binding keeps the handoff disabled and never authorizes", async () => {
  const result = await runHandoff({ gatewayOrigin: "https://example.org", nonce: "b".repeat(43), provider: "google", purpose: "login" }, "rejected");
  assert.equal(result.nodes.get("continue").disabled, true);
  assert.match(result.nodes.get("status").textContent, /could not be verified/);
  assert.equal(result.calls.includes("/handoff/authorize"), false);
});

async function runCallback(search) {
  const nodes = new Map(["status", "retry"].map(id => [id, {
    textContent: "", hidden: true, addEventListener() {},
  }]));
  const stored = new Map(), calls = [];
  const sessionStorage = { getItem: key => stored.get(key) ?? null,
    setItem: (key, value) => stored.set(key, value), removeItem: key => stored.delete(key) };
  const script = callback.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);
  await vm.runInNewContext(`(async () => { ${script} })()`, {
    document: { querySelector: selector => nodes.get(selector.slice(1)) },
    location: { search, pathname: "/callback/" }, history: { replaceState() {} },
    URLSearchParams, sessionStorage, Date,
    fetch: async (path, options) => { calls.push({ path, body: JSON.parse(options.body) }); return { status: 204, ok: true }; },
  });
  return { nodes, calls };
}

test("callback delivers successful and denied bound flows without legacy redirect", async () => {
  for (const [field, value] of [["code", "provider-code"], ["error", "access_denied"]]) {
    const result = await runCallback(`?state=k2.test&${field}=${value}`);
    assert.equal(result.calls.length, 1);
    assert.equal(result.calls[0].path, "/handoff/callback");
    assert.equal(result.calls[0].body[field], value);
    assert.match(result.nodes.get("status").textContent, field === "code" ? /Sign-in completed/ : /not completed/);
  }
  const legacy = await runCallback("?state=k1.old-ticket&code=provider-code");
  assert.equal(legacy.calls.length, 0);
  assert.match(legacy.nodes.get("status").textContent, /not valid/);
});
