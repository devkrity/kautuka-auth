// Browser-facing Gateway origins may use HTTP only on the supported local network.
export function isAllowedGatewayOrigin(value) {
  if (typeof value !== "string" || value.length > 2048 || /[%\\\u0000-\u0020\u007f]/.test(value)) return false;
  try {
    const url = new URL(value);
    if (url.origin !== value || url.username || url.password || url.hostname.endsWith(".")
      || /[^\x21-\x7e]/.test(url.hostname)
      || url.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) return false;
    return url.protocol === "https:" || (url.protocol === "http:" && isPrivateHost(url.hostname));
  } catch {
    return false;
  }
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
