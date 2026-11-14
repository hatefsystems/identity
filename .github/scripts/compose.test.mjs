import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createRequire } from 'node:module';
import { registrationUsernameFixture } from './registration-browser.mjs';

const require = createRequire(import.meta.url);
const { parse } = require('yaml');
const root = fileURLToPath(new URL('../../', import.meta.url));
const productionEnv = {
  API_IMAGE: 'ghcr.io/hatefsystems/identity-api:1.2.3',
  WEB_IMAGE: 'ghcr.io/hatefsystems/identity-web:1.2.3',
  POSTGRES_USER: 'owner',
  POSTGRES_DB: 'identity',
  POSTGRES_PASSWORD: 'test-owner',
  MIGRATION_DATABASE_URL: 'postgres://owner:test-owner@postgres:5432/identity',
  DATABASE_URL: 'postgres://api:test-api@postgres:5432/identity',
  REDIS_PASSWORD: 'test-redis',
  REDIS_URL: 'redis://:test-redis@redis:6379/0',
  PORTAL_ORIGIN: 'https://identity.example.com',
  OIDC_ISSUER: 'https://identity.example.com',
  WEBAUTHN_RP_ID: 'identity.example.com',
  WEBAUTHN_RP_ORIGINS: 'https://identity.example.com',
  TRUSTED_PROXY_CIDRS: '172.30.85.1/32',
  OIDC_CLIENTS_JSON: '[{"client_id":"test"}]',
  ENVELOPE_MASTER_KEK: 'test-kek',
  ENVELOPE_BLIND_INDEX_PEPPER: 'test-pepper',
  WEBAUTHN_MOCK_CHALLENGE_KEY: 'test-mock',
  STEPUP_REPLAY_HMAC_KEY: 'test-replay',
  OIDC_SIGNING_KEY_ACTIVE_PEM: 'test-active',
  OIDC_SIGNING_KEY_NEXT_PEM: 'test-next',
};
function renderConfig(file, env = {}) {
  return spawnSync(
    'docker',
    [
      'compose',
      '--env-file',
      '.env.production.example',
      ...[file].flat().flatMap((path) => ['-f', path]),
      'config',
      '--format',
      'json',
    ],
    {
      cwd: root,
      env: { ...process.env, ...env },
      encoding: 'utf8',
      windowsHide: true,
    }
  );
}
function config(file, env = {}) {
  const result = renderConfig(file, env);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('full local Compose renders with gated migration, persistent secrets and only HTTPS published', () => {
  const { services, volumes } = config('compose.yaml');
  assert.deepEqual(Object.keys(services).sort(), [
    'api',
    'ingress',
    'init',
    'migrate',
    'nats',
    'postgres',
    'redis',
    'web',
  ]);
  assert.equal(services.api.depends_on.migrate.condition, 'service_completed_successfully');
  assert.equal(services.api.depends_on.init.condition, 'service_completed_successfully');
  for (const service of ['redis', 'nats'])
    assert.equal(services.api.depends_on[service].condition, 'service_healthy');
  assert.equal(services.migrate.depends_on.postgres.condition, 'service_healthy');
  for (const [name, service] of Object.entries(services)) {
    if (name !== 'ingress') assert.equal(service.ports, undefined);
  }
  assert.equal(services.ingress.ports[0].host_ip, '127.0.0.1');
  assert.equal(services.ingress.ports[0].published, '8443');
  assert.equal(services.api.environment.APP_ENV, 'development');
  assert.equal(services.api.environment.PORTAL_ORIGIN, 'https://localhost:8443');
  assert.ok(
    services.api.volumes.some((volume) => volume.target === '/run/local-keys' && volume.read_only)
  );
  for (const volume of Object.values(volumes))
    assert.ok(volume.name.startsWith('hatef-idp-local_'));
  assert.deepEqual(Object.keys(services.ingress.networks).sort(), ['edge', 'ingress']);
  assert.equal(services.api.networks.edge, undefined);
  assert.equal(services.ingress.networks.default, undefined);
});

const registrationEnv = {
  ...registrationUsernameFixture().environment,
  SMS_GATEWAY_API_KEY: 'test-provider-key',
  SMS_IR_TEMPLATE_ID: '123',
  SMS_IR_CODE_PARAMETER: 'Code',
  SMS_OTP_HASH_PEPPER: Buffer.alloc(32, 7).toString('base64'),
  SMS_OTP_GLOBAL_PER_DAY: '10',
  REGISTRATION_PENDING_CAPACITY: '10',
  REGISTRATION_GLOBAL_DAILY_LIMIT: '10',
  REGISTRATION_EMAIL_HOURLY_LIMIT: '2',
  REGISTRATION_SMTP_HOST: 'smtp.example.invalid',
  REGISTRATION_SMTP_PORT: '587',
  REGISTRATION_SMTP_USERNAME: 'test-relay-user',
  REGISTRATION_SMTP_PASSWORD: 'test-relay-password',
  REGISTRATION_SMTP_FROM: 'identity@example.invalid',
  REGISTRATION_CLEANUP_PASSWORD: 'test-cleanup-password-'.repeat(3),
};

test('real signup overlay gates API on a dedicated worker without passing provider secrets to it', () => {
  const { services } = config(['compose.yaml', 'compose.registration.yaml'], registrationEnv);
  const env = services.api.environment;
  assert.equal(env.REGISTRATION_ENABLED, 'true');
  for (const [key, value] of Object.entries(registrationEnv)) {
    if (key.startsWith('USERNAME_')) {
      assert.ok(env[key] === value, `username fixture environment mismatch: ${key}`);
      assert.ok(services['registration-setup'].environment[key] === undefined, `${key} reached setup`);
      assert.ok(services['registration-cleanup'].environment[key] === undefined, `${key} reached cleanup`);
    }
  }
  assert.equal(env.SMS_ENABLED, 'true');
  assert.equal(env.SMS_IR_KEY_MODE, 'live');
  assert.equal(env.REGISTRATION_PENDING_CAPACITY, env.SMS_OTP_MAX_PENDING_SIGNUP);
  assert.equal(env.REGISTRATION_SMTP_PUBLIC_ORIGIN, env.PORTAL_ORIGIN);
  assert.equal(services.api.depends_on['registration-cleanup'].condition, 'service_healthy');
  assert.equal(
    services['registration-cleanup'].depends_on['registration-setup'].condition,
    'service_completed_successfully'
  );
  assert.deepEqual(Object.keys(services['registration-cleanup'].depends_on).sort(), [
    'postgres',
    'registration-setup',
  ]);
  assert.deepEqual(Object.keys(services['registration-setup'].depends_on), ['migrate']);
  assert.deepEqual(Object.keys(services.migrate.depends_on), ['postgres']);
  assert.match(env.REGISTRATION_CLEANUP_DATABASE_URL, /\/\/identity_registration_cleanup:/);
  assert.deepEqual(Object.keys(services['registration-cleanup'].environment).sort(), [
    'APP_ENV',
    'REGISTRATION_CLEANUP_BATCH_SIZE',
    'REGISTRATION_CLEANUP_DATABASE_URL',
  ]);
  assert.equal(services['registration-setup'].environment.SMS_GATEWAY_API_KEY, undefined);
  assert.equal(services['registration-cleanup'].ports, undefined);
  assert.equal(services['registration-setup'].ports, undefined);
  assert.equal(config('compose.yaml').services.api.environment.REGISTRATION_ENABLED, 'false');
});

test('registration overlay refuses every missing username authority input instead of supplying defaults', async (t) => {
  for (const key of [
    'USERNAME_REGEX',
    'USERNAME_POLICY_JSON',
    'USERNAME_LOOKUP_KEY',
    'USERNAME_LOOKUP_KEY_ID',
  ]) {
    await t.test(key, () => {
      const result = renderConfig(['compose.yaml', 'compose.registration.yaml'], {
        ...registrationEnv,
        [key]: '',
      });
      assert.notEqual(result.status, 0);
      assert.ok(result.stderr.includes(key), 'missing authority must fail interpolation');
    });
  }
  assert.equal(config('compose.yaml').services.api.environment.USERNAME_ENABLED, undefined);
});

test('worker-only registration acceptance reuses explicit authority inputs without installing or activating them', () => {
  const source = readFileSync(
    new URL('../../tools/docker/smoke-registration-config.mjs', import.meta.url),
    'utf8'
  );
  assert.match(source, /import \{ registrationUsernameFixture \} from/);
  assert.match(source, /\.\.\.registrationUsernameFixture\(\)\.environment/);
  assert.doesNotMatch(source, /\.seedSQL|INSERT INTO public\.username_|UPDATE public\.username_active_policy/);
  assert.match(source, /admission_state='uninstalled'/);
  assert.match(source, /'provider test must not start API'/);
  assert.match(source, /throw new Error\('Local registration Compose command failed'\)/);
});

test('registration secrets file is ignored without excluding its public template', () => {
  const ignored = spawnSync(
    'git',
    [
      '-c',
      `safe.directory=${root.replaceAll('\\', '/').replace(/\/$/, '')}`,
      'check-ignore',
      '.env.registration',
    ],
    { cwd: root, encoding: 'utf8', windowsHide: true }
  );
  assert.equal(ignored.status, 0);
  const template = spawnSync(
    'git',
    [
      '-c',
      `safe.directory=${root.replaceAll('\\', '/').replace(/\/$/, '')}`,
      'check-ignore',
      '.env.registration.example',
    ],
    { cwd: root, encoding: 'utf8', windowsHide: true }
  );
  assert.equal(template.status, 1);
});

test('production renders without builds, owner credentials in API or public application ports', () => {
  const { services } = config('compose.production.yaml', productionEnv);
  for (const service of Object.values(services)) assert.equal(service.build, undefined);
  for (const name of ['api', 'web']) assert.equal(services[name].ports[0].host_ip, '127.0.0.1');
  for (const name of ['postgres', 'redis', 'nats']) assert.equal(services[name].ports, undefined);
  assert.equal(services.api.environment.APP_ENV, 'production');
  assert.equal(services.api.environment.SESSION_COOKIE_SECURE, 'true');
  assert.equal(services.api.environment.MIGRATION_DATABASE_URL, undefined);
  assert.equal(services.api.environment.POSTGRES_PASSWORD, undefined);
  assert.equal(services.migrate, undefined, 'operator-only migration profile is not started by up');
});

test('workflow publishes only after all existing gates and full-stack acceptance succeed', () => {
  const workflow = parse(
    readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8')
  );
  const publish = workflow.jobs.publish;
  for (const gate of [
    'quality',
    'security-db',
    'security-race',
    'frontend',
    'portal-browser',
    'admin-browser',
    'registration-browser',
    'compose-smoke',
  ]) {
    assert.ok(publish.needs.includes(gate), `missing publication gate ${gate}`);
  }
  assert.match(publish.if, /github\.event_name == 'push'/);
  assert.match(publish.if, /refs\/heads\/main/);
  assert.equal(publish.permissions.packages, 'write');
  for (const [name, job] of Object.entries(workflow.jobs)) {
    if (name !== 'publish') assert.notEqual(job.permissions?.packages, 'write');
  }
});
