import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { connect } from 'node:tls';
import test from 'node:test';
import {
  anonymousReclaim,
  assertLocalOrigin,
  browserFailure,
  fixtureSecretValues,
  portalRoute,
  redactFixtureSecrets,
  replicaFor,
  secretEnvironmentValues,
} from './portal-harness.mjs';
import { deletionMail, startMailSink } from './portal-mail-sink.mjs';

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
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim/options', request), 0);
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim', request), 1);
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim/', request), 1);
    assert.equal(replicaFor('/api/v1/users/me', request), request % 2);
  }
});

test('no-DPoP success exception covers only exact anonymous POST reclaim routes', () => {
  for (const path of ['/api/v1/auth/deletion/reclaim/options', '/api/v1/auth/deletion/reclaim', '/api/v1/auth/deletion/reclaim/']) {
    assert(anonymousReclaim(path, 'POST'));
    assert(!anonymousReclaim(path, 'GET'));
  }
  for (const path of ['/api/v1/users/me', '/api/v1/auth/deletion/reclaim/options/', '/api/v1/auth/deletion/reclaim/unknown', '/api/v1/auth/stepup/verify']) {
    assert(!anonymousReclaim(path, 'POST'));
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
    token: 'fixture-reclaim-token',
    link: 'https://localhost:43210/recover-account#token=fixture-reclaim-token',
    recipient: 'pending@fixture.example.test',
    database_url: 'postgres://fixture:private@localhost:43210/fixture',
    expires_at: '2026-10-25T00:00:30Z',
  };
  const secrets = fixtureSecretValues(fixture);
  assert(secrets.includes(fixture.code), 'Leading-zero TOTP codes must be kept as strings');
  assert(secrets.includes(fixture.credentials[0].privateKey));
  assert(secrets.includes(fixture.secret));
  assert(secrets.includes(fixture.key));
  assert(secrets.includes(fixture.otpauth_url));
  assert(secrets.includes(fixture.codes[0]));
  assert(secrets.includes(fixture.token));
  assert(secrets.includes(fixture.link));
  assert(secrets.includes(fixture.recipient));
  assert(secrets.includes(fixture.database_url));
  assert(secrets.includes('private'), 'Dedicated database password needs standalone redaction');
  assert(!secrets.includes(fixture.expires_at));
  const diagnostic = redactFixtureSecrets(`${JSON.stringify(fixture)}\n${secrets.join('\n')}`, secrets);
  for (const secret of secrets) {
    assert(!diagnostic.includes(secret), 'Raw private fixture value escaped redaction');
    assert(!diagnostic.includes(JSON.stringify(secret).slice(1, -1)), 'Escaped private fixture value escaped redaction');
  }
  assert(diagnostic.includes(fixture.expires_at));
  assert.deepEqual(fixtureSecretValues({ code: '', secret: null }), []);
});

const mailRunID = '0123456789abcdef0123456789abcdef';
const mailPolicy = {
  origin: 'https://localhost:43210',
  from: `notices@${mailRunID}.example.test`,
  recipient: `pending@${mailRunID}.example.test`,
};
const mailToken = Buffer.alloc(32, 19).toString('base64url');
function sampleMail(link = `${mailPolicy.origin}/recover-account#token=${mailToken}`) {
  const body = (media, content) => `--deletion-fixture\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Type: ${media}; charset=UTF-8\r\n\r\n${content}\r\n`;
  const encoded = link.replaceAll('=', '=3D');
  return `From: <${mailPolicy.from}>\r\nTo: <${mailPolicy.recipient}>\r\nMessage-ID: <deletion.00000000-0000-4000-8000-000000000001@fixture.example.test>\r\nContent-Type: multipart/alternative; boundary="deletion-fixture"\r\n\r\n` +
    body('text/plain', `Recover until 2026-11-25T12:00:00Z (UTC)\r\n${encoded}`) +
    body('text/html', `<a href=3D"${encoded}">Recover account</a>`) + '--deletion-fixture--\r\n';
}

test('mail parser accepts bounded canonical fragment links and rejects leaks', () => {
  const mail = deletionMail(sampleMail(), mailPolicy);
  assert.equal(mail.token, mailToken);
  assert.equal(mail.expires_at, '2026-11-25T12:00:00Z');
  assert.deepEqual(Object.keys(mail).sort(), ['expires_at', 'link', 'message_id', 'recipient', 'token']);
  for (const link of [
    `https://remote.example.test/recover-account#token=${mailToken}`,
    `${mailPolicy.origin}/recover-account?token=${mailToken}`,
    `${mailPolicy.origin}/recover-account#token=${mailToken}=` ,
    `${mailPolicy.origin}/recover-account#token=${'A'.repeat(42)}B`,
    `${mailPolicy.origin}/other#token=${mailToken}`,
  ]) assert.throws(() => deletionMail(sampleMail(link), mailPolicy));
  assert.throws(() => deletionMail(sampleMail().replace('Recover account</a>', 'Recover account</a><img src=3D"https://remote.example.test/pixel">'), mailPolicy));
  assert.throws(() => deletionMail(sampleMail() + 'x'.repeat(32 * 1024), mailPolicy));
});

test('owned mail sink requires verified TLS/auth, rejects foreign recipients, and captures retry identity in memory', { timeout: 15000 }, async () => {
  const parent = join(tmpdir(), 'kilo');
  mkdirSync(parent, { recursive: true });
  const directory = mkdtempSync(join(parent, 'portal-mail-test-'));
  let sink;
  const clients = [];
  try {
    const keyPath = join(directory, 'key.pem');
    const certPath = join(directory, 'cert.pem');
    const certificate = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-subj', '/CN=localhost', '-days', '1',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], { encoding: 'utf8', timeout: 5000 });
    assert(certificate.status === 0 && !certificate.error, 'Cannot create ephemeral test certificate');
    const cert = readFileSync(certPath);
    const secrets = [];
    sink = await startMailSink({
      ...mailPolicy, runID: mailRunID, cert, key: readFileSync(keyPath),
      username: 'fixture-user', password: 'fixture-password', onSecrets: (values) => secrets.push(...values),
    });
    const untrusted = connect({ host: '127.0.0.1', port: sink.port });
    clients.push(untrusted);
    await assert.rejects(once(untrusted, 'secureConnect'));
    const socket = connect({ host: '127.0.0.1', port: sink.port, ca: cert, minVersion: 'TLSv1.2' });
    clients.push(socket);
    await once(socket, 'secureConnect');
    assert(socket.authorized, 'Fixture TLS was not verified');
    const lines = createInterface({ input: socket, crlfDelay: Infinity })[Symbol.asyncIterator]();
    const response = async () => {
      let line;
      do {
        const result = await lines.next();
        assert(!result.done, 'Fixture relay closed unexpectedly');
        line = result.value;
      } while (line[3] === '-');
      return Number(line.slice(0, 3));
    };
    const send = async (value) => { socket.write(`${value}\r\n`); return response(); };
    assert.equal(await response(), 220);
    assert.equal(await send('EHLO identity.invalid'), 250);
    assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 530);
    assert.equal(await send(`AUTH PLAIN ${Buffer.from('\0fixture-user\0wrong').toString('base64')}`), 535);
    assert.equal(await send(`AUTH PLAIN ${Buffer.from('\0fixture-user\0fixture-password').toString('base64')}`), 235);
    assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 250);
    assert.equal(await send('RCPT TO:<foreign@another.example.test>'), 550);
    assert.throws(() => sink.rejectNext('foreign@another.example.test'));
    sink.rejectNext(mailPolicy.recipient);
    for (const result of [451, 250]) {
      assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 250);
      assert.equal(await send(`RCPT TO:<${mailPolicy.recipient}>`), 250);
      assert.equal(await send('DATA'), 354);
      assert.equal(await send(sampleMail() + '.'), result);
    }
    const accepted = await sink.waitFor(mailPolicy.recipient);
    assert.equal(accepted.token, mailToken);
    assert.equal(sink.messages.length, 2);
    assert.equal(sink.messages[0].message_id, accepted.message_id);
    assert.equal(sink.messages[0].token, accepted.token);
    assert.equal(sink.messages[0].expires_at, accepted.expires_at);
    assert.deepEqual(sink.evidence, { tls: 1, authenticated: 1, authRejected: 1, recipientRejected: 1, temporary: 1, accepted: 1 });
    assert(secrets.includes(mailToken) && secrets.includes(accepted.link));
    await send('QUIT');
  } finally {
    for (const socket of clients) socket.destroy();
    await sink?.close();
    rmSync(directory, { recursive: true, force: true });
  }
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
