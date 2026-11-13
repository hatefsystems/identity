// Prove local role/worker provisioning on a fresh owned database. Never start
// the HTTP API or contact the supplied real SMS/SMTP providers in this check.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCommand } from '../../.github/scripts/release-images.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
process.chdir(root);
const project = `ldp-registration-check-${randomUUID().replaceAll('-', '')}`;
const temp = await mkdtemp(join(tmpdir(), 'ldp-registration-check-'));
const password = randomBytes(32).toString('hex');
const fixture = {
  SMS_GATEWAY_API_KEY: 'isolated-test-no-provider',
  SMS_IR_TEMPLATE_ID: '1',
  SMS_IR_CODE_PARAMETER: 'Code',
  SMS_OTP_HASH_PEPPER: randomBytes(32).toString('base64'),
  SMS_OTP_GLOBAL_PER_DAY: '1',
  REGISTRATION_PENDING_CAPACITY: '1',
  REGISTRATION_GLOBAL_DAILY_LIMIT: '1',
  REGISTRATION_EMAIL_HOURLY_LIMIT: '1',
  REGISTRATION_SMTP_HOST: 'smtp.example.invalid',
  REGISTRATION_SMTP_PORT: '587',
  REGISTRATION_SMTP_USERNAME: 'test-relay',
  REGISTRATION_SMTP_PASSWORD: 'unused-test-password',
  REGISTRATION_SMTP_FROM: 'identity@example.invalid',
  REGISTRATION_CLEANUP_PASSWORD: password,
};
const envFile = join(temp, 'fixture.env');
await writeFile(
  envFile,
  Object.entries(fixture)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n'),
  { mode: 0o600 }
);
const compose = (args, overrides = {}) =>
  runCommand(
    'docker',
    [
      'compose',
      '-p',
      project,
      '--env-file',
      envFile,
      '-f',
      join(root, 'compose.yaml'),
      '-f',
      join(root, 'compose.registration.yaml'),
      ...args,
    ],
    { timeout: 180_000, env: { ...process.env, ...fixture, ...overrides } }
  );
const sql = (query) =>
  compose([
    'exec',
    '-T',
    'postgres',
    'psql',
    '-X',
    '-U',
    'identity',
    '-d',
    'identity',
    '-Atc',
    query,
  ]);
const check = (overrides) =>
  compose(
    [
      'run',
      '--rm',
      '--no-deps',
      '--entrypoint',
      '/usr/local/bin/registration-cleanup',
      'registration-cleanup',
      'check',
    ],
    overrides
  );
try {
  await compose([
    'up',
    '-d',
    '--no-build',
    '--wait',
    '--wait-timeout',
    '150',
    'registration-cleanup',
  ]);
  await check();
  const before = await sql(
    "SELECT rolpassword FROM pg_authid WHERE rolname='identity_registration_cleanup'"
  );
  assert.ok(before.startsWith('SCRAM-SHA-256$'), 'cleanup login must have a SCRAM password');
  await compose(['run', '--rm', '--no-deps', 'registration-setup']);
  const after = await sql(
    "SELECT rolpassword FROM pg_authid WHERE rolname='identity_registration_cleanup'"
  );
  assert.ok(before === after, 'repeat provisioning must preserve existing credentials');
  await assert.rejects(
    () => check({ REGISTRATION_CLEANUP_PASSWORD: randomBytes(32).toString('hex') }),
    /failed/
  );
  await compose(['stop', 'registration-cleanup']);
  await sql('GRANT SELECT ON public.users TO identity_registration_cleanup');
  try {
    await assert.rejects(() => check(), /failed/);
  } finally {
    await sql('REVOKE SELECT ON public.users FROM identity_registration_cleanup');
  }
  await check();
  await assert.rejects(
    () =>
      compose(['run', '--rm', '--no-deps', 'registration-setup'], {
        REGISTRATION_CLEANUP_PASSWORD: 'invalid@password',
      }),
    /failed/
  );
  const logs = await compose([
    'logs',
    '--no-color',
    'registration-setup',
    'registration-cleanup',
    'postgres',
  ]);
  assert.ok(!logs.includes(password), 'role setup must not disclose the plaintext password');
  assert.equal(
    (await compose(['ps', '--status', 'running', '-q', 'api'])).trim(),
    '',
    'provider test must not start API'
  );
} finally {
  await compose(['down', '--volumes', '--remove-orphans']);
  assert.equal((await compose(['ps', '-a', '-q'])).trim(), '', 'owned containers must be retired');
  await rm(temp, { recursive: true, force: true });
}
console.log(
  'Local registration cleanup credentials, least privileges, supervision and owned teardown passed; no messages sent.'
);
