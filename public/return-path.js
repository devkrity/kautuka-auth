const loginProviders = new Set(["kautuka-login-google", "kautuka-login-microsoft"]);
const mailProviders = new Set(["kautuka-google-mail", "kautuka-m365-mail"]);

export function returnPathFor(connector) {
  if (loginProviders.has(connector)) return "/login/callback";
  if (mailProviders.has(connector)) return "/connectors";
  return null;
}

export function isCanonicalOrigin(value) {
  if (typeof value !== "string" || value.length > 300 || /[%\\\u0000-\u0020\u007f]/.test(value)) return false;
  try {
    const url = new URL(value);
    return url.origin === value && url.protocol === "https:" && url.pathname === "/"
      && !url.username && !url.password && !url.search && !url.hash
      && !url.hostname.endsWith(".") && !url.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))
      && !/[^\x21-\x7e]/.test(url.hostname);
  } catch {
    return false;
  }
}

export function isAllowedReturn(value, connector) {
  const path = returnPathFor(connector);
  if (!path || typeof value !== "string" || value.length > 3000) return false;
  if (/[%\\\u0000-\u0020\u007f]/.test(value)) return false;

  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.href !== value || url.username || url.password || url.pathname !== path || url.search || url.hash) return false;
  if (url.hostname.endsWith(".") || /[^\x21-\x7e]/.test(url.hostname)) return false;
  if (url.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) return false;
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  return isPrivateHost(url.hostname);
}

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") return true;
  if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.local$/.test(host)) return true;
  if (host.startsWith("[")) {
    const firstGroup = host.slice(1, -1).split(":")[0];
    const group = Number.parseInt(firstGroup || "0", 16);
    return Number.isInteger(group) && group >= 0xfc00 && group <= 0xfdff;
  }

  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [first, second] = octets;
  return first === 10
    || first === 127
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}
