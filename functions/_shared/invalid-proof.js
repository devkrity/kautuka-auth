// Called only after the coarse pre-authentication budget has allowed the request.
export async function rejectInvalidProof(env, ip, headers, status = 400) {
  if (!env.INVALID_REQUEST_LIMIT) return new Response("not configured", { status: 503, headers });
  try {
    if (!(await env.INVALID_REQUEST_LIMIT.limit({ key: ip })).success)
      return new Response("too many requests", { status: 429, headers: { ...headers, "retry-after": "60" } });
  } catch { return new Response("temporarily unavailable", { status: 503, headers }); }
  return new Response("rejected", { status, headers });
}
