import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createRequire } from 'node:module';

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
function config(file, env = {}) {
  const result = spawnSync(
    'docker',
    ['compose', '--env-file', '.env.production.example', '-f', file, 'config', '--format', 'json'],
    {
      cwd: root,
      env: { ...process.env, ...env },
      encoding: 'utf8',
      windowsHide: true,
    }
  );
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
