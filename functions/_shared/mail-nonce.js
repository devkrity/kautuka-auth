// The internal 428 is emitted only before the Durable Object starts a mail operation.
export function mailNonceChallenge(response) {
  if (response.status === 423) return suspendedInstallation();
  if (response.status !== 428) return null;
  const nonce = response.headers.get("dpop-nonce");
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce ?? ""))
    return new Response("temporarily unavailable", { status: 503, headers: { "cache-control": "no-store" } });
  return Response.json({ error: "use_dpop_nonce" }, {
    status: 400, headers: { "cache-control": "no-store", "dpop-nonce": nonce },
  });
}

export function suspendedInstallation() {
  return Response.json({ error: "installation_suspended" }, {
    status: 403, headers: { "cache-control": "no-store", "kautuka-installation-error": "installation_suspended" },
  });
}
