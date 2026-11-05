// Microsoft documents an omitted scope in the code-exchange response as the
// originally requested scopes. Google documents returning the granted scopes.
export function hasRequiredMailScopes(provider, scope) {
  if (scope === undefined) return provider === 'microsoft';
  if (typeof scope !== 'string' || !scope.trim() || scope.length > 16384) return false;
  const granted = new Set(scope.trim().split(/\s+/));
  if (provider === 'google') return granted.has('https://www.googleapis.com/auth/gmail.modify');
  if (provider !== 'microsoft') return false;
  const graphScopes = new Set([...granted].map(value => value.toLowerCase()).map(value =>
    value.startsWith('https://graph.microsoft.com/') ? value.slice('https://graph.microsoft.com/'.length) : value));
  return ['mail.readwrite', 'mail.send', 'user.read'].every(value => graphScopes.has(value));
}
