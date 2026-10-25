import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  assertLocalOrigin,
  browserFailure,
  fixtureSecretValues,
  portalRoute,
  redactFixtureSecrets,
  replicaFor,
  secretEnvironmentValues,
} from './portal-harness.mjs';

test('portal harness refuses HTTP, remote, and noncanonical origins', () => {
  assert.equal(assertLocalOrigin('https://localhost:43210').port, '43210');
  for (const value of [
    'http://localhost:43210',
    'https://identity.example.test:43210',
    'https://localhost:43210/',
    'https://localhost:43210/path',
    'https://user@localhost:43210',
    'https://localhost',
  ])
    assert.throws(() => assertLocalOrigin(value));
});

test('ceremony starts and nonce retries stay on A, completions stay on B', () => {
  for (let request = 0; request < 4; request++) {
    for (const flow of ['login', 'register']) {
      assert.equal(replicaFor(`/api/v1/auth/webauthn/${flow}/generate-options`, request), 0);
      assert.equal(replicaFor(`/api/v1/auth/webauthn/${flow}/verify`, request), 1);
    }
    assert.equal(replicaFor('/api/v1/auth/stepup/challenge', request), 0);
    assert.equal(replicaFor('/api/v1/auth/stepup/verify', request), 1);
    assert.equal(replicaFor('/api/v1/users/me', request), request % 2);
  }
});

test('portal diagnostics use route templates rather than credential/session IDs', () => {
  assert.equal(
    portalRoute('/api/v1/auth/webauthn/keys/not-a-log-field'),
    '/api/v1/auth/webauthn/keys/{id}'
  );
  assert.equal(
    portalRoute('/api/v1/users/me/sessions/not-a-log-field'),
    '/api/v1/users/me/sessions/{id}'
  );
  assert.equal(portalRoute('/api/v1/users/me'), '/api/v1/users/me');
});

test('browser failures never print request headers, bodies or locator values', () => {
  const failure = new Error('cookie: PRIVATE-COOKIE dpop: PRIVATE-PROOF grant: PRIVATE-GRANT');
  failure.stack += '\n    at loseResponse (web-portal.browser.mjs:975:34)';
  const message = browserFailure(failure, 'uncertain-recovery');
  assert.match(message, /uncertain-recovery.*web-portal\.browser\.mjs:975:34/);
  assert.doesNotMatch(message, /PRIVATE-|cookie:|grant:|dpop:/);
  assert.match(browserFailure(failure, 'SECRET USER VALUE'), /during unknown/);
});

test('portal diagnostics redact secrets without treating key versions as secrets', () => {
  const signing = 's'.repeat(32);
  const replay = 'r'.repeat(32);
  const envelope = 'e'.repeat(32);
  assert.deepEqual(
    secretEnvironmentValues({
      OIDC_SIGNING_KEY_ACTIVE_PEM: signing,
      STEPUP_REPLAY_HMAC_KEY: replay,
      ENVELOPE_MASTER_KEK: envelope,
      ENVELOPE_MASTER_KEK_VERSION: '1',
      WEBAUTHN_RESIDENT_KEY: 'required',
    }),
    [signing, replay, envelope]
  );
});

test('captured fixture codes and secrets are redacted, including JSON-escaped material', () => {
  const fixture = {
    user_id: 'owned-fixture-subject',
    email: 'owned@fixture.example.test',
    credentials: [{ privateKey: 'fixture-private-key', signCount: 0 }],
    code: '004219',
    secret: 'fixture-authenticator-secret',
    otpauth_url: 'otpauth://totp/fixture?secret=fixture-authenticator-secret',
    key: 'private\nTLS\nkey',
    codes: ['one-time-recovery-code'],
    expires_at: '2026-10-25T00:00:30Z',
  };
  const secrets = fixtureSecretValues(fixture);
  assert(secrets.includes(fixture.code), 'Leading-zero TOTP codes must be kept as strings');
  assert(secrets.includes(fixture.credentials[0].privateKey));
  assert(secrets.includes(fixture.secret));
  assert(secrets.includes(fixture.key));
  assert(secrets.includes(fixture.otpauth_url));
  assert(secrets.includes(fixture.codes[0]));
  assert(!secrets.includes(fixture.expires_at));
  const diagnostic = redactFixtureSecrets(`${JSON.stringify(fixture)}\n${secrets.join('\n')}`, secrets);
  for (const secret of secrets) {
    assert(!diagnostic.includes(secret), 'Raw private fixture value escaped redaction');
    assert(!diagnostic.includes(JSON.stringify(secret).slice(1, -1)), 'Escaped private fixture value escaped redaction');
  }
  assert(diagnostic.includes(fixture.expires_at));
  assert.deepEqual(fixtureSecretValues({ code: '', secret: null }), []);
});

test('fixture and replicas share one ephemeral KEK and a run-owned audit stream before migration', () => {
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  const shared = harness.slice(harness.indexOf('const storeEnv ='), harness.indexOf('const fixture ='));
  assert.match(shared, /ENVELOPE_MASTER_KEK: randomBytes\(32\)\.toString\('base64'\)/);
  assert.match(shared, /ENVELOPE_MASTER_KEK_VERSION: '1'/);
  assert.match(shared, /AUDIT_STREAM_NAME: `PORTAL_BROWSER_AUDIT_\$\{runID\}`/);
  assert.match(shared, /secrets\.push\(\.\.\.secretEnvironmentValues\(storeEnv\)\)/);
  assert.equal(harness.match(/ENVELOPE_MASTER_KEK:/g)?.length, 1);
  assert.equal(harness.match(/AUDIT_STREAM_NAME:/g)?.length, 1);
  const fixture = harness.slice(harness.indexOf('const fixture ='), harness.indexOf("fixture('migrate')"));
  assert.match(fixture, /\.\.\.storeEnv/);
  assert.match(fixture, /fixtureSecretValues\(input\)/);
  assert.match(fixture, /fixtureSecretValues\(value\)/);
  assert.doesNotMatch(fixture, /result\.stderr/);
  assert.match(harness.slice(harness.indexOf('const apiEnvironment =')), /\.\.\.storeEnv/);
});

test('CI preserves image/CSP coverage and gates release on the real portal suite', () => {
  const workflow = readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8');
  assert.match(workflow, /web-csp\.browser\.mjs/);
  assert.match(workflow, /smoke-image\.mjs api identity-api:ci/);
  assert.match(workflow, /nx run web:test-portal-browser --skipNxCache/);
  assert.match(workflow, /nx run identity-api:test-portal-integration --skipNxCache/);
  assert.match(workflow, /needs: \[quality, security-db, frontend, portal-browser\]/);
});

test('portal integration cannot silently omit real dependencies or run in parallel', () => {
  const { targets } = JSON.parse(
    readFileSync(new URL('../../apps/identity-api/project.json', import.meta.url), 'utf8')
  );
  const target = targets['test-portal-integration'];
  assert.equal(target.cache, false);
  assert.equal(target.parallelism, false);
  for (const contract of [
    'DATABASE_URL',
    'REDIS_URL',
    'NATS_URL',
    'REQUIRE_PORTAL_INTEGRATION',
    'REQUIRE_PROFILE_INTEGRATION',
    '-tags=integration',
    '-p=1',
    './internal/profile',
    './internal/webauthn',
    './internal/session',
  ]) {
    assert(
      target.options.command.includes(contract),
      `Missing integration requirement ${contract}`
    );
  }
});

test('credential fixture is opt-in and not packaged into the production API image', () => {
  const fixture = readFileSync(
    new URL('../../apps/identity-api/cmd/portal-fixture/main.go', import.meta.url),
    'utf8'
  );
  const dockerfile = readFileSync(
    new URL('../../apps/identity-api/Dockerfile', import.meta.url),
    'utf8'
  );
  assert(fixture.startsWith('//go:build portalfixture\n'));
  assert.match(fixture, /PORTAL_FIXTURE_ALLOW/);
  assert.match(fixture, /portal_browser_/);
  assert(!dockerfile.includes('portal-fixture') && !dockerfile.includes('portalfixture'));
});
