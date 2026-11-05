const idPattern = /^[A-Za-z0-9_-]{43}$/;
const encode = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");

export async function issueFlowReference(env, origin, id, flowId, state) {
  if (typeof env.AUTH_TICKET_HMAC_KEY !== "string" || env.AUTH_TICKET_HMAC_KEY.length < 32
    || ![id, flowId, state].every((value) => typeof value === "string" && idPattern.test(value))) return null;
  const payload = `k2.${id}.${flowId}.${state}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.AUTH_TICKET_HMAC_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${origin}:${payload}`));
  return `${payload}.${encode(signature)}`;
}

export async function readFlowReference(env, origin, reference) {
  if (typeof reference !== "string" || reference.length > 256) return null;
  const parts = reference.split(".");
  if (parts.length !== 5 || parts[0] !== "k2" || !parts.slice(1).every((part) => idPattern.test(part))) return null;
  const expected = await issueFlowReference(env, origin, parts[1], parts[2], parts[3]);
  if (!expected) return null;
  // HMAC comparison through WebCrypto avoids string-comparison timing differences.
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.AUTH_TICKET_HMAC_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const raw = parts[4].replaceAll("-", "+").replaceAll("_", "/");
  const decoded = Uint8Array.from(atob(`${raw}=`), (char) => char.charCodeAt(0));
  if (encode(decoded) !== parts[4]) return null;
  const payload = parts.slice(0, 4).join(".");
  if (!await crypto.subtle.verify("HMAC", key, decoded, new TextEncoder().encode(`${origin}:${payload}`))) return null;
  return { id: parts[1], flowId: parts[2], state: parts[3] };
}
