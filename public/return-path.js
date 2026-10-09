const loginProviders = new Set(["kautuka-login-google", "kautuka-login-microsoft"]);
const mailProviders = new Set(["kautuka-google-mail", "kautuka-m365-mail"]);

export function returnPathFor(connector) {
  if (loginProviders.has(connector)) {
    return "/login/callback";
  }

  if (mailProviders.has(connector)) {
    return "/connectors";
  }

  return null;
}

export function isAllowedReturn(value, connector) {
  const expected = returnPathFor(connector);
  if (!expected || !value) {
    return false;
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.username || url.password) {
    return false;
  }

  if (url.pathname !== expected || url.search || url.hash) {
    return false;
  }

  if (url.protocol === "https:") {
    return true;
  }

  if (url.protocol !== "http:") {
    return false;
  }

  return isPrivateHost(url.hostname);
}

function isPrivateHost(host) {
  const name = host.toLowerCase();
  if (name === "localhost" || name === "127.0.0.1" || name === "::1" || name.endsWith(".local")) {
    return true;
  }

  const parts = name.split(".").map(Number);
  if (parts.length === 4 && parts.every((part) => part >= 0 && part <= 255)) {
    if (parts[0] === 10) {
      return true;
    }

    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return true;
    }

    if (parts[0] === 192 && parts[1] === 168) {
      return true;
    }
  }

  return false;
}
