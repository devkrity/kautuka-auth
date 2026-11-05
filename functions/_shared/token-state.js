function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url");
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decodeKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error("Invalid AES key encoding");
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function readKeyring(env) {
  let keyring;
  try {
    keyring = JSON.parse(env.REFRESH_TOKEN_KEYS);
  } catch {
    return null;
  }
  if (!keyring || Array.isArray(keyring) || typeof keyring !== "object") return null;
  const activeKid = env.REFRESH_TOKEN_ACTIVE_KID;
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(activeKid ?? "") || typeof keyring[activeKid] !== "string") return null;
  try {
    if (decodeKey(keyring[activeKid]).length !== 32) return null;
  } catch {
    return null;
  }
  return { keyring, activeKid };
}

export function isKeyringReady(env) {
  return readKeyring(env) !== null;
}

export async function sealSocialFlowResult(env, installationId, flowId, idToken) {
  const keys = readKeyring(env);
  if (!keys || !/^[A-Za-z0-9_-]{43}$/.test(installationId) || !/^[A-Za-z0-9_-]{43}$/.test(flowId)
    || typeof idToken !== "string" || idToken.length < 20 || idToken.length > 20000) throw new Error("Invalid flow result");
  const key = await crypto.subtle.importKey("raw", decodeKey(keys.keyring[keys.activeKid]), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv,
    additionalData: new TextEncoder().encode(`social:${installationId}:${flowId}`) }, key, new TextEncoder().encode(idToken));
  return `kfr1.${keys.activeKid}.${encodeBase64Url(iv)}.${encodeBase64Url(new Uint8Array(ciphertext))}`;
}

export async function openSocialFlowResult(env, installationId, flowId, envelope) {
  const keys = readKeyring(env);
  if (!keys || !/^[A-Za-z0-9_-]{43}$/.test(installationId) || !/^[A-Za-z0-9_-]{43}$/.test(flowId)
    || typeof envelope !== "string" || envelope.length > 40000) return null;
  const [version, kid, encodedIv, encodedCiphertext, ...extra] = envelope.split(".");
  if (version !== "kfr1" || extra.length || !/^[A-Za-z0-9_-]{1,32}$/.test(kid ?? "") || typeof keys.keyring[kid] !== "string") return null;
  try {
    const iv = decodeBase64Url(encodedIv);
    const ciphertext = decodeBase64Url(encodedCiphertext);
    if (iv.length !== 12 || ciphertext.length < 17) return null;
    const key = await crypto.subtle.importKey("raw", decodeKey(keys.keyring[kid]), "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv,
      additionalData: new TextEncoder().encode(`social:${installationId}:${flowId}`) }, key, ciphertext);
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch { return null; }
}

export async function sealMailFlowResult(env, installationId, flowId, dpopJkt, result) {
  const keys = readKeyring(env);
  if (!keys || ![installationId, flowId, dpopJkt].every((v) => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v))
    || typeof result !== "string" || !result || result.length > 32000) throw new Error("Invalid mail flow result");
  const plaintext = new TextEncoder().encode(result);
  if (plaintext.length > 32000) throw new Error("Invalid mail flow result");
  const key = await crypto.subtle.importKey("raw", decodeKey(keys.keyring[keys.activeKid]), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv,
    additionalData: new TextEncoder().encode(`mail:${installationId}:${flowId}:${dpopJkt}`) }, key, plaintext);
  return `kmf1.${keys.activeKid}.${encodeBase64Url(iv)}.${encodeBase64Url(new Uint8Array(ciphertext))}`;
}

export async function openMailFlowResult(env, installationId, flowId, dpopJkt, envelope) {
  const keys = readKeyring(env);
  if (!keys || ![installationId, flowId, dpopJkt].every((v) => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v))
    || typeof envelope !== "string" || envelope.length > 60000) return null;
  const [version, kid, encodedIv, encodedCiphertext, ...extra] = envelope.split(".");
  if (version !== "kmf1" || extra.length || !/^[A-Za-z0-9_-]{1,32}$/.test(kid ?? "") || typeof keys.keyring[kid] !== "string") return null;
  try {
    const iv = decodeBase64Url(encodedIv);
    const ciphertext = decodeBase64Url(encodedCiphertext);
    if (iv.length !== 12 || ciphertext.length < 17) return null;
    const key = await crypto.subtle.importKey("raw", decodeKey(keys.keyring[kid]), "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv,
      additionalData: new TextEncoder().encode(`mail:${installationId}:${flowId}:${dpopJkt}`) }, key, ciphertext);
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch { return null; }
}

export async function wrapRefreshToken(env, provider, jkt, token) {
  const keys = readKeyring(env);
  if (!keys) throw new Error("Refresh token keyring is not configured");
  if (typeof token !== "string" || token.length === 0 || token.length > 8192) throw new Error("Invalid refresh token");

  const keyBytes = decodeKey(keys.keyring[keys.activeKid]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`${provider}:${jkt}`) },
    key,
    new TextEncoder().encode(token),
  );
  return `krt1.${keys.activeKid}.${encodeBase64Url(iv)}.${encodeBase64Url(new Uint8Array(ciphertext))}`;
}

export async function unwrapRefreshToken(env, provider, jkt, envelope) {
  const keys = readKeyring(env);
  if (!keys || typeof envelope !== "string" || envelope.length > 12000) return null;

  const [version, kid, encodedIv, encodedCiphertext, ...extra] = envelope.split(".");
  if (version !== "krt1" || extra.length !== 0 || !/^[A-Za-z0-9_-]{1,32}$/.test(kid ?? "")) return null;
  if (typeof keys.keyring[kid] !== "string") return null;

  try {
    const keyBytes = decodeKey(keys.keyring[kid]);
    const iv = decodeBase64Url(encodedIv);
    const ciphertext = decodeBase64Url(encodedCiphertext);
    if (keyBytes.length !== 32 || iv.length !== 12 || ciphertext.length < 17) return null;

    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`${provider}:${jkt}`) },
      key,
      ciphertext,
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    return null;
  }
}

export async function dpopState(env, provider, jkt, payload) {
  if (!env.DPOP_STATE) return null;
  try {
    const id = env.DPOP_STATE.idFromName(`${provider}:${jkt}`);
    const stub = env.DPOP_STATE.get(id);
    const response = await stub.fetch("https://state.internal/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider, jkt, ...payload }),
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

