import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { loginMail } from './portal-mail-sink.mjs';
import { fixtureSecretValues, portalRoute, replicaFor } from './portal-harness.mjs';
import { assertLoginChallenge, loginJourneys } from './login-browser.mjs';

const from = 'notices@0123456789abcdef0123456789abcdef.example.test';
const recipient = 'login@0123456789abcdef0123456789abcdef.example.test';
const code = '019283';
const expires = '2026-11-20T16:30:00.123456789Z';
function message() {
  return `From: <${from}>\r\nTo: <${recipient}>\r\nSubject: Your account sign-in code\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nEnter this code only in the browser where you started signing in:\r\n${code}\r\n\r\nThis sign-in code expires at ${expires}. It cannot verify a signup or change your contacts. If you did not request it, ignore this message.\r\n`;
}

test('login sender sink captures only bounded code, recipient and original deadline', () => {
  assert.deepEqual(loginMail(message(), { from, recipient }), { kind: 'login', recipient, code, expires_at: expires });
  for (const corrupt of [message().replace(code, '01928'), message().replace(code, '۰۱۹۲۸۳'),
    message().replace('text/plain', 'text/html'), message().replace('MIME-Version:', 'Bcc:'),
    message().replace(recipient, from), message() + 'private body', message() + 'x'.repeat(32 * 1024)])
    assert.throws(() => loginMail(corrupt, { from, recipient }));
});

test('login challenge schemas contain no destination, session or unexpected authority', () => {
  for (const stage of ['mfa', 'delivered']) {
    const key = stage === 'mfa' ? 'preauthentication' : 'challenge';
    const value = { status: stage === 'mfa' ? 'mfa_required' : 'code_requested', [key]: randomBytes(32).toString('base64url'), expires_at: expires };
    assert.equal(assertLoginChallenge(value, stage), value);
    for (const field of ['email', 'username', 'session', 'password'])
      assert.throws(() => assertLoginChallenge({ ...value, [field]: 'private' }, stage));
    assert.throws(() => assertLoginChallenge({ ...value, [key]: 'invalid' }, stage));
  }
});

test('credential matrix retains all configurations and strong versus contact-code admin evidence', () => {
  assert.deepEqual([...new Set(loginJourneys.map((item) => item.credentials))].sort(), ['dual', 'passkey-only', 'password-only']);
  assert(loginJourneys.some((item) => item.method === 'email' && item.mfa && item.role === 'support'));
  assert(loginJourneys.some((item) => item.method === 'password' && item.mfa && item.role === 'support'));
  assert(loginJourneys.some((item) => item.method === 'passkey' && item.mfa && item.role === 'support'));
});

test('login capabilities and credential fixture values stay private but routes remain sanitized', () => {
  const values = { username: 'private-account', phone: '+989123456789', password: 'private password',
    preauthentication: 'private-preauth', challenge: 'private-challenge', code: '012345', expires_at: expires };
  const secrets = fixtureSecretValues(values);
  for (const field of ['username', 'phone', 'password', 'preauthentication', 'challenge', 'code']) assert(secrets.includes(values[field]));
  assert(!secrets.includes(expires));
  for (const path of ['/api/v1/auth/login', '/api/v1/auth/login/code/request', '/api/v1/auth/login/code/verify', '/api/v1/auth/login/mfa']) {
    assert.equal(portalRoute(path + '?private=secret'), path);
    assert(!portalRoute(path + '/private-capability').includes('private-capability'));
  }
  assert.equal(replicaFor('/api/v1/auth/login/code/verify', 0), 1);
});
