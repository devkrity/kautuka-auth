export async function verifyDpop(dpop, grantType, _code, target) {
  if (typeof dpop !== "string" || dpop.length > 4000
    || !["authorization_code", "refresh_token", "revoke"].includes(grantType)) return { ok: false };
  const parts = dpop.split(".");
  if (parts.length !== 3 || parts[2].length !== 86) return { ok: false };

  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  } catch {
    return { ok: false };
  }

  const jwk = header?.jwk;
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !jwk || jwk.d
    || jwk.kty !== "EC" || jwk.crv !== "P-256"
    || typeof jwk.x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
    || typeof jwk.y !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jwk.y)) return { ok: false };
  if (payload.htm !== target.htm || payload.htu !== target.htu) return { ok: false };

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number" || !Number.isSafeInteger(payload.iat) || Math.abs(now - payload.iat) > 300
    || typeof payload.jti !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(payload.jti)
    || payload.nonce !== undefined && (typeof payload.nonce !== "string" || payload.nonce.length > 200)) return { ok: false };

  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signatureValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      decodeBase64Url(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!signatureValid) return { ok: false };
    return { ok: true, jkt: await thumbprint(jwk), jti: payload.jti, nonce: typeof payload.nonce === "string" ? payload.nonce : "" };
  } catch {
    return { ok: false };
  }
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return encodeBase64Url(new Uint8Array(digest));
}

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
