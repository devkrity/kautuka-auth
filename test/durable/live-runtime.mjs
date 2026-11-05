import assert from "node:assert/strict";

const baseUrl = process.env.AUTH_TEST_BASE_URL;
const previewOrigin = "https://broker-controls-kautuka-auth.aged-star-69fb.workers.dev";
const isPreview = process.env.AUTH_TEST_CLOUDFLARE_PREVIEW === "1" && baseUrl === previewOrigin;
if (!baseUrl?.startsWith("https://127.0.0.1:") && !isPreview)
  throw new Error("Use an HTTPS loopback Worker, or explicitly select the isolated broker-controls preview.");
const origin = new URL(baseUrl).origin;
if (origin !== baseUrl) throw new Error("AUTH_TEST_BASE_URL must be an HTTPS origin without a path or trailing slash.");
const encode = (value) => Buffer.from(value).toString("base64url");
const body = JSON.stringify({ id: encode(crypto.getRandomValues(new Uint8Array(32))) });
const target = `${origin}/installation/register`;
const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

async function signedRequest(key, requestTarget = target, requestBody = body) {
  const exported = await crypto.subtle.exportKey("jwk", key.publicKey);
  const jwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
  const now = Math.floor(Date.now() / 1000);
  const head = encode(JSON.stringify({ typ: "kautuka-installation+jwt", alg: "ES256", jwk }));
  const payload = encode(JSON.stringify({ aud: origin, htm: "POST", htu: requestTarget, iat: now, exp: now + 60,
    jti: encode(crypto.getRandomValues(new Uint8Array(32))), body_hash: encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(requestBody))) }));
  const signature = encode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(`${head}.${payload}`)));
  return { method: "POST", headers: { "content-type": "application/json", ...(isPreview ? {} : { "CF-Connecting-IP": "127.0.0.1" }),
    "Kautuka-Installation-Proof": `${head}.${payload}.${signature}` }, body: requestBody };
}

const legacy = await fetch(`${origin}/google-mail/token`, { method: "POST" });
assert.equal(legacy.status, 410);
assert.equal(legacy.headers.get("x-frame-options"), "DENY");
const first = await signedRequest(pair);
const responses = await Promise.all([fetch(target, first), fetch(target, first)]);
assert.deepEqual(responses.map((response) => response.status).sort(), [204, 409]);
const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
assert.equal((await fetch(target, await signedRequest(other))).status, 409);
assert.equal((await fetch(target, await signedRequest(pair))).status, 204);
const replacement = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const publicKey = await crypto.subtle.exportKey("jwk", replacement.publicKey);
const canonical = JSON.stringify({ crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x, y: publicKey.y });
const rotationBody = JSON.stringify({ id: JSON.parse(body).id, operationId: encode(crypto.getRandomValues(new Uint8Array(32))),
  replacementThumbprint: encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))) });
const rotationTarget = `${origin}/installation/rotate`;
async function rotationRequest(replacementKey) {
  const oldRequest = await signedRequest(pair, rotationTarget, rotationBody);
  const newRequest = await signedRequest(replacementKey, rotationTarget, rotationBody);
  oldRequest.headers["Kautuka-Replacement-Proof"] = newRequest.headers["Kautuka-Installation-Proof"];
  return oldRequest;
}
assert.equal((await fetch(rotationTarget, await rotationRequest(other))).status, 400);
assert.equal((await fetch(rotationTarget, await rotationRequest(replacement))).status, 204);
assert.equal((await fetch(rotationTarget, await rotationRequest(replacement))).status, 204);
assert.equal((await fetch(target, await signedRequest(pair))).status, 409);
assert.equal((await fetch(target, await signedRequest(replacement))).status, 204);
console.log(`${isPreview ? "Isolated Cloudflare preview" : "Local Worker"} retired-route, Durable Object replay and key-rotation checks passed.`);
