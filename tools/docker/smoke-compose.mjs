// Own one fresh Compose project; never attach to or remove a developer stack.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request } from 'node:https';

const root = fileURLToPath(new URL('../../', import.meta.url));
assert.notEqual(
  process.env.NODE_TLS_REJECT_UNAUTHORIZED,
  '0',
  'Compose acceptance requires real TLS verification'
);
const project = `ldp-compose-check-${randomUUID().replaceAll('-', '')}`;
const temp = await mkdtemp(join(tmpdir(), 'ldp-compose-check-'));
function compose(args, { allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', ['compose', '-p', project, '-f', 'compose.yaml', ...args], {
      cwd: root,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '';
    child.stdout.on('data', (part) => {
      stdout += part;
    });
    child.stderr.on('data', (part) => {
      stderr += part;
    });
    child.on('error', reject);
    child.on('close', (code) =>
      code === 0 || allowFailure
        ? resolve({ code, stdout, stderr })
        : reject(new Error(`Compose ${args[0]} failed: ${stderr.slice(-4000)}`))
    );
  });
}
let ca;
function get(path) {
  return new Promise((resolve, reject) => {
    const req = request(`https://localhost:8443${path}`, { ca, timeout: 10000 }, (response) => {
      let body = '';
      response.on('data', (part) => {
        body += part;
      });
      response.on('end', () =>
        resolve({
          status: response.statusCode,
          headers: response.headers,
          body,
          policyCount: response.rawHeaders.filter(
            (value, index) => index % 2 === 0 && value.toLowerCase() === 'content-security-policy'
          ).length,
        })
      );
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('HTTPS probe timeout')));
    req.end();
  });
}
try {
  await compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '180']);
  await compose(['cp', 'init:/run/local-tls/ca.crt', join(temp, 'ca.crt')]);
  ca = await readFile(join(temp, 'ca.crt'));
  const first = await get('/login');
  const second = await get('/login');
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const nonce = (response) =>
    /'nonce-([^']+)'/.exec(response.headers['content-security-policy'])?.[1];
  assert.ok(nonce(first));
  assert.equal(first.policyCount, 1);
  assert.notEqual(nonce(first), nonce(second));
  assert.ok(first.body.includes(`nonce="${nonce(first)}"`));
  assert.match(first.headers['cache-control'], /no-store/);
  const assetPath = /(?:src|href)="(\/_next\/static\/[^\"]+)"/.exec(first.body)?.[1];
  assert.ok(assetPath, 'production document must reference static assets');
  const asset = await get(assetPath);
  assert.equal(asset.status, 200);
  assert.match(asset.headers['cache-control'], /immutable/);
  assert.equal((await get('/readyz')).status, 200);
  const discovery = await get('/.well-known/openid-configuration');
  assert.equal(discovery.status, 200);
  assert.equal(JSON.parse(discovery.body).issuer, 'https://localhost:8443');
  assert.equal((await get('/oauth2/jwks')).status, 200);
  assert.equal((await get('/this-page-does-not-exist')).status, 404);
  const hashes = () => compose(['exec', '-T', 'api', 'sh', '-c', 'sha256sum /run/local-keys/*']);
  const before = (await hashes()).stdout;
  await compose(['exec', '-T', 'redis', 'redis-cli', 'set', 'compose-smoke', 'persistent']);
  await compose([
    'exec',
    '-T',
    'postgres',
    'psql',
    '-U',
    'identity',
    '-d',
    'identity',
    '-c',
    "COMMENT ON DATABASE identity IS 'compose-smoke'",
  ]);
  await compose(['run', '--rm', '--no-deps', 'migrate', 'up']);
  await compose(['run', '--rm', '--no-deps', 'init']);
  assert.equal((await hashes()).stdout, before, 'initialization must reuse keys');
  await compose(['restart', 'postgres', 'redis', 'nats', 'api', 'web', 'ingress']);
  await compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '180']);
  assert.equal((await hashes()).stdout, before, 'restart must preserve keys');
  assert.equal(
    (await compose(['exec', '-T', 'redis', 'redis-cli', 'get', 'compose-smoke'])).stdout.trim(),
    'persistent'
  );
  assert.equal(
    (
      await compose([
        'exec',
        '-T',
        'postgres',
        'psql',
        '-U',
        'identity',
        '-d',
        'identity',
        '-Atc',
        "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname='identity'",
      ])
    ).stdout.trim(),
    'compose-smoke'
  );
  assert.equal((await get('/readyz')).status, 200);
  assert.equal((await get('/login')).status, 200);
  // Deliberately damage only this run's keys, then prove init fails and restore.
  await compose([
    'run',
    '--rm',
    '--no-deps',
    '--user',
    '0:0',
    '--entrypoint',
    '/bin/sh',
    'init',
    '-ec',
    'mv /run/local-keys/ENVELOPE_MASTER_KEK /run/local-keys/saved-kek',
  ]);
  try {
    const invalid = await compose(['run', '--rm', '--no-deps', 'init'], { allowFailure: true });
    assert.notEqual(invalid.code, 0, 'partial initialization must fail');
    await compose(['stop', 'api', 'ingress']);
    const gated = await compose(['up', '-d', '--no-build', 'api'], { allowFailure: true });
    assert.notEqual(gated.code, 0, 'failed initialization must block API startup');
    assert.equal((await compose(['ps', '--status', 'running', '-q', 'api'])).stdout.trim(), '');
  } finally {
    await compose([
      'run',
      '--rm',
      '--no-deps',
      '--user',
      '0:0',
      '--entrypoint',
      '/bin/sh',
      'init',
      '-ec',
      'mv /run/local-keys/saved-kek /run/local-keys/ENVELOPE_MASTER_KEK',
    ]);
  }
  // Override only this isolated project's migration command; no schema corruption.
  const override = join(temp, 'failed-migration.yaml');
  await writeFile(override, 'services:\n  migrate:\n    command: [not-a-command]\n');
  const failedMigration = await compose(['-f', override, 'up', '-d', '--no-build', 'api'], {
    allowFailure: true,
  });
  assert.notEqual(failedMigration.code, 0);
  assert.equal((await compose(['ps', '--status', 'running', '-q', 'api'])).stdout.trim(), '');
  await compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '180']);
  assert.equal((await get('/readyz')).status, 200);
} finally {
  await compose(['down', '--volumes', '--remove-orphans']);
  assert.equal(
    (await compose(['ps', '-a', '-q'])).stdout.trim(),
    '',
    'owned Compose containers must be retired'
  );
  await rm(temp, { recursive: true, force: true });
}
console.log(
  'Full-stack HTTPS, CSP, migration, persistent keys/data, restart, failure gates and owned cleanup passed.'
);
