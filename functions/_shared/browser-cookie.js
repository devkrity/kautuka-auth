const prefix = "__Host-kautuka-broker-";
const valuePattern = /^[A-Za-z0-9_-]{43}$/;

export function getOrCreateBrowserCookie(request, flowId) {
  if (typeof flowId !== "string" || !valuePattern.test(flowId)) return null;
  const name = prefix + flowId;
  const values = (request.headers.get("cookie") ?? "").split(";")
    .map((part) => part.trim()).filter((part) => part.startsWith(`${name}=`))
    .map((part) => part.slice(name.length + 1));
  if (values.length > 1 || values.length === 1 && !valuePattern.test(values[0])) return null;
  if (values.length === 1) return { value: values[0], header: null };
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const value = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  return { value, header: `${name}=${value}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax` };
}

export function getExistingBrowserCookie(request, flowId) {
  const cookie = getOrCreateBrowserCookie(request, flowId);
  return cookie && cookie.header === null ? cookie.value : null;
}

export async function hashBrowserCookie(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
