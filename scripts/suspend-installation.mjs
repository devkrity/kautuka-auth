// Operator secret is read from stdin, never a command-line argument.
import { randomBytes } from "node:crypto";

const [originArg, id, reason] = process.argv.slice(2);
const identifier = /^[A-Za-z0-9_-]{43}$/;
let origin;
try {
  const parsed = new URL(originArg);
  if (parsed.protocol !== "https:" || parsed.origin !== originArg || parsed.username || parsed.password) throw new Error();
  origin = parsed.origin;
} catch { throw new Error("Supply the broker HTTPS origin without a trailing slash."); }
if (!identifier.test(id ?? "") || !/^[a-z0-9_-]{1,64}$/.test(reason ?? ""))
  throw new Error("Supply an installation ID and a short lowercase reason code.");
let secret = "";
for await (const chunk of process.stdin) {
  secret += chunk;
  if (secret.length > 256) throw new Error("Invalid operator secret input.");
}
secret = secret.trim();
if (!/^[A-Za-z0-9_-]{43,128}$/.test(secret)) throw new Error("Invalid operator secret input.");
const operationId = randomBytes(32).toString("base64url");
const response = await fetch(`${origin}/operator/installations/suspend`, {
  method: "POST", redirect: "error", headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
  body: JSON.stringify({ id, operationId, reason }), signal: AbortSignal.timeout(15000),
});
if (!response.ok) throw new Error(`Suspension failed with HTTP ${response.status}; retry only after checking the target and operator configuration.`);
const result = await response.json();
if (!["suspended", "already_suspended"].includes(result.status)) throw new Error("Unexpected broker response.");
console.log(`Broker ${origin}, installation ${id}: ${result.status}.`);
console.log("Provider grants and already issued access tokens are not revoked by this action.");
