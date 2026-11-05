import assert from 'node:assert/strict';
import test from 'node:test';
import { hasRequiredMailScopes } from '../functions/_shared/mail-scopes.js';

test('mail grants require each provider capability, without accepting scope lookalikes', () => {
  assert.equal(hasRequiredMailScopes('google', 'openid https://www.googleapis.com/auth/gmail.modify'), true);
  assert.equal(hasRequiredMailScopes('google', 'openid profile'), false);
  assert.equal(hasRequiredMailScopes('google', 'https://www.googleapis.com/auth/gmail.modify.extra'), false);
  assert.equal(hasRequiredMailScopes('google', undefined), false);
  assert.equal(hasRequiredMailScopes('microsoft', 'openid Mail.ReadWrite Mail.Send User.Read'), true);
  assert.equal(hasRequiredMailScopes('microsoft', 'https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read'), true);
  assert.equal(hasRequiredMailScopes('microsoft', 'Mail.ReadWrite User.Read'), false);
  assert.equal(hasRequiredMailScopes('microsoft', 'Mail.ReadWrite Mail.Send https://attacker.example/User.Read'), false);
  assert.equal(hasRequiredMailScopes('microsoft', undefined), true);
  assert.equal(hasRequiredMailScopes('microsoft', null), false);
  assert.equal(hasRequiredMailScopes('other', undefined), false);
});
