const contentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export async function onRequest(context) {
  let path;
  try { path = decodeURIComponent(new URL(context.request.url).pathname).toLowerCase().replace(/\/+$/, "") || "/"; }
  catch { return new Response("rejected", { status: 400, headers: { "cache-control": "no-store" } }); }
  // Coordinated breaking cutover: the former ticket/callback and token routes
  // did not enforce installation, browser, account or generation binding.
  const retired = new Set(["/authorize", "/start/confirm", "/callback/validate", "/login/google/token", "/login/microsoft/token",
    "/google-mail/token", "/microsoft-mail/token"]);
  const blocked = retired.has(path) || /^\/(google-mail|microsoft-mail)\/keys(?:\/|$)/.test(path);
  const response = blocked ? new Response("This sign-in flow has been retired.", { status: 410, headers: { "cache-control": "no-store" } })
    : await context.next();
  const headers = new Headers(response.headers);

  headers.set("Content-Security-Policy", contentSecurityPolicy);
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
