import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { access, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { createServer as tcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startMailSink } from './portal-mail-sink.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const backend = resolve(workspace, 'apps/identity-api');
const canonicalUUID = (value) => typeof value === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
  value !== '00000000-0000-0000-0000-000000000000';

export function legalIdempotencyKey(path, method, value) {
  if (value === undefined) return;
  assert(method === 'POST' && ['/api/v1/admin/legal-holds', '/api/v1/admin/preservation-requests'].includes(path) &&
    canonicalUUID(value), 'Invalid scoped legal operation key');
  return value;
}

export function legalReferenceRequest(request, secret, harness) {
  try {
    const url = new URL(request.url());
    if (url.origin !== harness.origin || url.hash || request.isNavigationRequest?.() || !canonicalUUID(secret)) return false;
    if (request.method() === 'DELETE' && harness.legalReferences?.holds.has(secret))
      return url.pathname === `/api/v1/admin/legal-holds/${secret}` && !url.href.includes('?');
    if (request.method() !== 'GET' || url.pathname !== '/api/v1/admin/legal-holds' ||
        !harness.legalReferences?.accounts.has(secret)) return false;
    if (url.searchParams.get('account_ref') !== secret) return false;
    // Only the explicitly typed filter may carry a reference. Never generalize
    // the exception to other queries, document navigation, or diagnostic paths.
    const seen = new Set();
    for (const [key, value] of url.searchParams) {
      if (seen.has(key) || !['account_ref', 'status', 'limit', 'offset'].includes(key)) return false;
      seen.add(key);
      if (key !== 'account_ref' && value.includes(secret)) return false;
      if (key === 'status' && !['active', 'released', 'all'].includes(value)) return false;
      if ((key === 'limit' || key === 'offset') && (!/^(0|[1-9][0-9]*)$/.test(value) ||
          Number(value) > 2147483647 || (key === 'limit' && value === '0'))) return false;
    }
    decodeURIComponent(url.search);
    return true;
  } catch { return false; }
}

export function legalCoordinateRequest(request, value, harness) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value) ||
      BigInt(value) > 9223372036854775807n || !harness.legalSecrets?.has(value) ||
      request.method() !== 'GET' || request.isNavigationRequest?.() !== false) return false;
  try {
    const url = new URL(request.url());
    if (url.origin !== harness.origin || url.username || url.password || url.hash) return false;
    const logs = url.pathname === '/api/v1/admin/audit-logs';
    if (!logs && !['/api/v1/admin/audit-logs/verify', '/api/v1/admin/ledger/verify'].includes(url.pathname)) return false;
    const coordinates = logs ? ['before_seq'] : ['after_seq', 'through_seq'];
    const keys = logs ? ['before_seq', 'start_time', 'end_time', 'event_type', 'limit']
      : ['after_seq', 'through_seq', 'predecessor_hash', 'limit'];
    let matched = false;
    for (const [key, item] of url.searchParams) {
      if (!keys.includes(key) || url.searchParams.getAll(key).length !== 1 || key.includes(value)) return false;
      if (item.includes(value)) {
        if (!coordinates.includes(key) || item !== value) return false;
        matched = true;
      }
    }
    decodeURIComponent(url.search);
    return matched;
  } catch { return false; }
}

export function portalResponseBudget(path, method) {
  return (method === 'GET' && ['/api/v1/admin/audit-logs', '/api/v1/admin/legal-holds'].includes(path)) ||
    (method === 'POST' && path === '/api/v1/admin/legal-inquiry/lookup') ? 4 * 1024 * 1024 : 256 * 1024;
}

export function capturePortalJSON(response, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let failed = false;
    const fail = () => {
      failed = true;
      chunks.length = 0;
      reject(new Error('Bounded upstream response capture failed'));
    };
    const declared = response.headers['content-length'];
    if (declared !== undefined && (!/^\d+$/.test(declared) || BigInt(declared) > BigInt(limit))) fail();
    response.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) fail();
      if (!failed) chunks.push(chunk);
    });
    response.once('error', fail);
    response.once('aborted', fail);
    response.once('end', () => {
      if (failed) return;
      try {
        assert(/^application\/json\b/i.test(response.headers['content-type'] || ''));
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch { fail(); }
      finally { chunks.length = 0; }
    });
  });
}

export function lookupProbeFixture(result) {
  assert(!result.error && result.status === 0 && typeof result.stdout === 'string' &&
    Buffer.byteLength(result.stdout) <= 64 * 1024, 'Real signer lookup probe failed; private diagnostics suppressed');
  const matches = [...result.stdout.matchAll(/^ADMIN_LOOKUP_FIXTURE_ID=([^\r\n]+)\r?$/gm)];
  assert(matches.length === 1 && canonicalUUID(matches[0][1]), 'Real signer lookup probe returned no unique canonical fixture');
  return matches[0][1];
}

export function portalRoute(path) {
  // Never echo arbitrary paths: identifiers can also occupy an unknown route,
  // and query/fragment values may contain emails, narratives, or credentials.
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) return '[redacted-route]';
  const pathname = path.split(/[?#]/, 1)[0];
  for (const [pattern, template] of [
    [/^\/api\/v1\/auth\/webauthn\/keys\/[^/]+$/, '/api/v1/auth/webauthn/keys/{id}'],
    [/^\/api\/v1\/users\/me\/sessions\/[^/]+$/, '/api/v1/users/me/sessions/{id}'],
    [/^\/api\/v1\/admin\/users\/[^/]+\/status\/?$/, '/api/v1/admin/users/{id}/status'],
    [/^\/api\/v1\/admin\/users\/(?!lookup\/?$)[^/]+\/?$/, '/api/v1/admin/users/{id}'],
    [/^\/api\/v1\/admin\/legal-holds\/[^/]+\/?$/, '/api/v1/admin/legal-holds/{hold_id}'],
    [/^\/admin\/users\/[^/]+\/?$/, '/admin/users/{id}'],
  ]) {
    if (pattern.test(pathname)) return template;
  }
  if (/^\/api\/v1\/(?:admin\/(?:capabilities|users(?:\/lookup)?|audit-logs(?:\/verify)?|ledger\/verify|legal-holds|preservation-requests|legal-inquiry\/lookup)|users\/me(?:\/(?:sessions|profile|deletion))?|auth\/(?:logout|session|stepup\/(?:challenge|verify)|webauthn\/(?:keys|(?:login|register)\/(?:generate-options|verify))|mfa\/totp\/(?:setup|enable|disable)|recovery-codes\/(?:generate|status|verify)|deletion\/reclaim(?:\/options)?))\/?$/.test(pathname) ||
      /^\/(?:admin(?:\/(?:users|audit-logs|integrity|legal))?|dashboard(?:\/(?:profile|security|sessions|privacy))?|login(?:\/webauthn)?|recover-account)$/.test(pathname)) return pathname;
  return '[redacted-route]';
}

export function replicaFor(path, sequence) {
  // Explicitly cross processes for portal and anonymous recovery ceremonies, including
  // nonce retries. Round-robin alone could put every successful retry on B.
  if (path === '/api/v1/auth/deletion/reclaim/options') return 0;
  if (path === '/api/v1/auth/deletion/reclaim' || path === '/api/v1/auth/deletion/reclaim/') return 1;
  if (path.endsWith('/generate-options') || path.endsWith('/stepup/challenge')) return 0;
  if (path.endsWith('/verify')) return 1;
  return sequence % 2;
}

export function anonymousReclaim(path, method) {
  return method === 'POST' && [
    '/api/v1/auth/deletion/reclaim/options',
    '/api/v1/auth/deletion/reclaim',
    '/api/v1/auth/deletion/reclaim/',
  ].includes(path);
}

export function privateLogSummary(text, secrets) {
  const contains = (source, value) => source.includes(value) || source.includes(encodeURIComponent(value)) ||
    source.includes(JSON.stringify(value).slice(1, -1));
  const matches = [...new Set(secrets)].filter((value) => typeof value === 'string' && value && contains(text, value));
  const kinds = {};
  for (const value of matches) {
    const kind = /^[0-9]+$/.test(value) ? 'numeric' : canonicalUUID(value) ? 'reference'
      : /^[^\s@]+@[^\s@]+$/.test(value) ? 'identity' : 'text';
    kinds[kind] = (kinds[kind] ?? 0) + 1;
  }
  const fields = new Set();
  const known = ['time', 'timestamp', 'level', 'msg', 'message', 'error', 'seq', 'sequence', 'last_seq',
    'through_seq', 'head_seq', 'checkpoint', 'count', 'request_id', 'account_ref', 'user_id', 'subject', 'path', 'url', 'method', 'status'];
  for (const line of text.split('\n')) {
    try {
      const record = JSON.parse(line);
      for (const key of known) if (record && key in record && matches.some((value) => contains(JSON.stringify(record[key]) ?? '', value))) fields.add(key);
    } catch { /* Only fixed field labels are diagnostic; raw lines are never returned. */ }
  }
  return { matches: matches.length, kinds, fields: [...fields].sort() };
}

export function secretEnvironmentValues(environment) {
  return Object.entries(environment)
    .filter(
      ([key, value]) => /KEY|KEK|SECRET|PEPPER|PASSWORD|TOKEN/.test(key) && typeof value === 'string' && value.length >= 32
    )
    .map(([, value]) => value);
}

export function fixtureSecretValues(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, item]) => {
    if (key === 'database_url' && typeof item === 'string') {
      try {
        return [item, decodeURIComponent(new URL(item).password)].filter(Boolean);
      } catch {
        return [item];
      }
    }
    if (/(?:^id$|_id$|(?:^|_)account_ref$|^actor_spiffe_id$|^credentialId$|^userHandle$|^code$|^secret$|^totp_secret$|^otpauth_url$|^privateKey$|^key$|email$|^recipient$|token$|^link$|^recovery_url$|^database_url$|^password$|reason|narrative|payload|^identifier$|^requesting_authority$|^legal_basis$|^case_reference$|^purpose$|cursor$|^seq$|^through_seq$|^client_ip$|^ip_subnet$|^user_agent$|^device_fingerprint$)/i.test(key)) {
      if (item && typeof item === 'object') return [JSON.stringify(item), ...fixtureSecretValues(item)];
      return typeof item === 'string' && item ? [item] : [];
    }
    if (key === 'codes' && Array.isArray(item)) {
      return item.filter((code) => typeof code === 'string' && code);
    }
    return fixtureSecretValues(item);
  });
}

export function fixtureRouteReferences(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, item]) =>
    ['user_id', 'session_id', 'credentialId'].includes(key) && typeof item === 'string'
      ? [item] : fixtureRouteReferences(item)
  );
}

export function redactFixtureSecrets(text, secrets) {
  const values = [...new Set(secrets)]
    .filter((value) => typeof value === 'string' && value)
    .sort((a, b) => b.length - a.length);
  for (const value of values) {
    text = text.replaceAll(value, '[fixture redacted]');
    text = text.replaceAll(JSON.stringify(value).slice(1, -1), '[fixture redacted]');
  }
  return text;
}

export function failureCategories(output) {
  if (typeof output !== 'string') return [];
  const categories = [];
  for (const [category, pattern] of [
    ['configuration', /\bconfig:/i],
    ['governance', /governance|baseline/i],
    ['key-material', /missing.*key|key.*required|OIDC.*KEY/i],
    ['timeout', /timeout|deadline exceeded|context canceled/i],
    ['connection', /connection refused|unable to connect|failed to connect/i],
    ['chain-data', /canonical|invalid envelope|payload.*invalid/i],
    ['stream-setup', /create or update stream/i],
    ['consumer-setup', /create or update consumer/i],
    ['connection-config', /parse.*config|parse.*dsn/i],
    ['transport', /TRANSPORT|unsupported/i],
    ['admin-retention-config', /requires explicit origins and approved context/],
    ['admin-window-config', /admin window must/],
    ['admin-origin-config', /admin origins require HTTPS/],
    ['durable-head', /invalid durable ledger state|read .* chain head|read .* head: no rows/i],
    ['legal-fixture-signing', /real signer did not index owned legal evidence|owned legal signing interrupted|cannot inspect real owned legal signing/],
    ['legal-fixture-subject', /cannot (?:create|remove signed|prepare soft-deleted) owned legal subject|cannot prepare soft-deleted legal subject/],
    ['legal-fixture-publication', /owned legal publication was not acknowledged|cannot connect owned legal producer/],
  ]) if (pattern.test(output)) categories.push(category);
  for (const setting of ['APP_ENV', 'PORT', 'PORTAL_ORIGIN', 'GRPC_PORT', 'AUDIT_BATCH_SIZE', 'AUDIT_FLUSH_INTERVAL', 'AUDIT_ACK_WAIT', 'AUDIT_SUBJECT', 'NATS_URL', 'SECURITY_LEDGER_RETENTION', 'ADMIN_GOVERNANCE_POLICY_ID', 'ADMIN_ALLOWED_ORIGINS', 'ADMIN_PAGE_SIZE_DEFAULT', 'ADMIN_PAGE_SIZE_MAX', 'ADMIN_CHAIN_VERIFY_MAX_LIMIT']) {
    if (new RegExp(`(^|[^A-Z0-9_])${setting}($|[^A-Z0-9_])`).test(output)) categories.push(`setting-${setting}`);
  }
  return [...categories, ...new Set([...output.matchAll(/\bSQLSTATE[ :]+([0-9A-Z]{5})/g)].map((match) => `sqlstate-${match[1]}`))].slice(0, 12);
}

export function browserFailure(error, stage = 'unknown') {
  const kind = error?.name === 'AssertionError' ? 'assertion' : 'operation';
  const location = typeof error?.stack === 'string'
    ? error.stack.match(/(?:web-(?:portal|admin|csp)\.browser|portal-harness|browser-localization)\.mjs:\d+:\d+/)?.[0]
    : undefined;
  const checkpoint = /^[a-z-]{1,64}$/.test(stage) ? stage : 'unknown';
  // Browser exception messages can embed full Cookie/DPoP/grant headers or DOM
  // values. Source coordinates and a fixed checkpoint are enough to investigate.
  return `Portal browser ${kind} failed during ${checkpoint}${location ? ` at ${location}` : ''}; sensitive exception details suppressed.`;
}

export function guardBrowserFailures(close) {
  let failed = false;
  const fail = () => {
    if (failed) return;
    failed = true;
    process.exitCode = 1;
    console.error('Browser callback failed; sensitive exception details suppressed.');
    void Promise.resolve().then(close)
      .catch(() => console.error('Disposable browser cleanup did not complete.'))
      .finally(() => process.exit(1));
  };
  process.on('unhandledRejection', fail);
  process.on('uncaughtException', fail);
  return () => {
    process.off('unhandledRejection', fail);
    process.off('uncaughtException', fail);
  };
}

export function assertLocalOrigin(value) {
  const origin = new URL(value);
  assert.equal(origin.protocol, 'https:', 'Portal browser tests require HTTPS');
  assert.equal(origin.hostname, 'localhost', 'Portal tests must not target a deployed service');
  assert(origin.port && origin.origin === value, 'Expected an exact ephemeral localhost origin');
  return origin;
}

function docker(args, allowFailure = false) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  if (result.error || (!allowFailure && result.status !== 0)) {
    throw new Error(`Disposable Docker ${args[0]} failed; sensitive process diagnostics suppressed`);
  }
  return result;
}

export function portalCleanup(resources) {
  let closing;
  // Cache before running any disposer, including concurrent or reentrant close.
  return () => closing ||= Promise.resolve().then(async () => {
    let failed = false;
    while (resources.length) {
      const dispose = resources.pop();
      try { await dispose(); } catch { failed = true; }
    }
    if (failed) throw new Error('Disposable portal cleanup did not complete; sensitive exception details suppressed.');
    return { completed: true };
  });
}

async function waitFor(check, description, timeout = 60_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await check()) return;
    await delay(200);
  }
  throw new Error(`Timed out waiting for ${description}`);
}

async function freePort() {
  const server = tcpServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function cleanEnvironment() {
  // Do not inherit a developer's DATABASE_URL, signing keys, admin/gRPC flags,
  // proxy settings, peppers, or credential state into acceptance fixtures.
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      /^(?:path|systemroot|windir|comspec|pathext|temp|tmp|home|userprofile|lang|lc_all)$/i.test(
        key
      )
    )
  );
}

export async function startPortalServices({ integration = false } = {}) {
  const runID = randomBytes(16).toString('hex');
  const name = `portal-browser-${runID}`;
  const database = `portal_browser_${runID}`;
  const password = randomBytes(24).toString('hex');
  const cleanup = [];
  const close = portalCleanup(cleanup);
  try {
    docker(['network', 'create', '--label', 'ldp.task=7.5', name]);
    cleanup.push(() => docker(['network', 'rm', name]));
    const container = async (suffix, ports, image, args = [], environment = {}) => {
      // The existing lifecycle restart test admits only this explicit broker
      // name/label. Never reuse it, or register cleanup before creation succeeds.
      const restartBroker = integration && suffix === 'nats';
      const id = restartBroker ? 'admin-test-nats' : `${name}-${suffix}`;
      // Docker reassigns automatic host bindings on restart. Explicit bindings
      // must be owned via create before a potentially failing port-binding start.
      const hostPorts = restartBroker ? await Promise.all(ports.map(() => freePort())) : ports.map(() => '');
      if (restartBroker) assert.equal(new Set(hostPorts).size, ports.length, 'Disposable broker ports overlapped');
      // A detached run may create the container before its start fails. Acquire
      // ownership first so every start failure has a registered disposer.
      docker(['create', '--name', id, '--network', name,
        '--label', restartBroker ? 'ldp.task=6.3' : 'ldp.task=7.5', '--label', `ldp.run=${runID}`,
        ...ports.flatMap((port, index) => ['--publish', `127.0.0.1:${hostPorts[index]}:${port}`]),
        ...Object.entries(environment).flatMap(([key, value]) => ['--env', `${key}=${value}`]), image, ...args]);
      cleanup.push(() => docker(['rm', '--force', '--volumes', id]));
      docker(['start', id]);
      const [state] = JSON.parse(docker(['inspect', id]).stdout);
      const exposed = Object.fromEntries(ports.map((port, index) => {
        const [binding] = state.NetworkSettings.Ports[`${port}/tcp`];
        assert.equal(binding.HostIp, '127.0.0.1');
        if (restartBroker) assert.equal(Number(binding.HostPort), hostPorts[index]);
        return [port, Number(binding.HostPort)];
      }));
      return { id, ports: exposed };
    };
    const postgres = await container('postgres', [5432], 'postgres:16-alpine', [], {
      POSTGRES_USER: 'portal', POSTGRES_PASSWORD: password, POSTGRES_DB: database,
    });
    const redis = await container('redis', [6379], 'redis:7-alpine', [
      'redis-server', '--save', '', '--appendonly', 'no', '--maxmemory', '96mb', '--maxmemory-policy', 'noeviction',
    ]);
    const nats = await container('nats', [4222, 8222], 'nats:2.10-alpine', ['-js', '-sd', '/data', '-m', '8222']);
    await waitFor(() => docker(['exec', postgres.id, 'pg_isready', '-h', '127.0.0.1', '-U', 'portal', '-d', database], true).status === 0, 'disposable PostgreSQL');
    await waitFor(() => docker(['exec', redis.id, 'redis-cli', 'ping'], true).stdout.trim() === 'PONG', 'disposable Redis');
    await waitFor(async () => {
      try {
        const response = await fetch(`http://127.0.0.1:${nats.ports[8222]}/healthz?js-enabled-only=true`, { signal: AbortSignal.timeout(1000), redirect: 'error' });
        return response.ok;
      } catch { return false; }
    }, 'disposable JetStream');
    return { runID, close, environment: {
      DATABASE_URL: `postgres://portal:${password}@127.0.0.1:${postgres.ports[5432]}/${database}?sslmode=disable`,
      REDIS_URL: `redis://127.0.0.1:${redis.ports[6379]}/0`,
      NATS_URL: `nats://127.0.0.1:${nats.ports[4222]}`,
      LIFECYCLE_TEST_NATS_CONTAINER: nats.id,
    } };
  } catch (error) {
    await close();
    throw error;
  }
}

export const integrationTargets = Object.freeze([
  'test-security-db', 'test-admin-integration', 'test-retention-integration',
  'test-legal-workflow-integration', 'test-grpc-integration',
  'test-lifecycle-integration', 'test-portal-integration',
]);

export async function runPortalIntegrationSuites() {
  // cleanEnvironment deliberately excludes ambient Go settings. Select the
  // checked-in module toolchain explicitly instead of inheriting a newer host Go.
  const goVersion = /^go ([0-9]+\.[0-9]+\.[0-9]+)$/m.exec(await readFile(resolve(backend, 'go.mod'), 'utf8'))?.[1];
  assert(goVersion, 'Missing pinned Go module version for integration validation');
  const services = await startPortalServices({ integration: true });
  try {
    // Separate Nx invocations are intentional: these suites reset schemas and
    // exercise broker outages. They must never overlap, even with Nx parallelism.
    for (const target of integrationTargets) {
      console.log(`Running identity-api:${target} on run-owned disposable services`);
      const child = spawn('npm', ['exec', '--', 'nx', 'run', `identity-api:${target}`, '--skipNxCache'], {
        cwd: workspace, env: {
          ...cleanEnvironment(), ...services.environment, NX_DAEMON: 'false', CI: 'true', FORCE_COLOR: '0',
          GOTOOLCHAIN: `go${goVersion}`, GOFLAGS: '-v', GOMAXPROCS: '2', REQUIRE_ADMIN_AUDIT_INTEGRATION: '1', REQUIRE_RETENTION_INTEGRATION: '1',
          REQUIRE_LIFECYCLE_INTEGRATION: '1', REQUIRE_PORTAL_INTEGRATION: '1',
          REQUIRE_PROFILE_INTEGRATION: '1', REQUIRE_GRPC_INTEGRATION: '1', REQUIRE_LEGAL_WORKFLOW_INTEGRATION: '1',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      // Test failures can contain bodies and identifiers. Keep only aggregate
      // package outcomes, never raw driver or assertion diagnostics.
      const outcomes = { packages: 0, tests: 0, failed: 0, skipped: 0 };
      const locations = new Set();
      const failures = new Set();
      const categories = new Set();
      let pending = '';
      const record = (chunk) => {
        const lines = (pending + String(chunk)).split('\n');
        pending = lines.pop().slice(-4096);
        for (const line of lines) {
          for (const category of failureCategories(line)) if (categories.size < 12) categories.add(category);
          if (/^ok\s/.test(line)) outcomes.packages++;
          if (/^\s*--- PASS:/.test(line)) outcomes.tests++;
          if (/^\s*--- FAIL:/.test(line)) outcomes.failed++;
          if (/^\s*--- SKIP:/.test(line)) outcomes.skipped++;
          const test = line.match(/^\s*--- FAIL: (Test[A-Za-z0-9_]+)/)?.[1];
          if (test && failures.size < 30) failures.add(test);
          const source = line.match(/(?:^|\s)([a-zA-Z0-9_]+\.go:\d+(?::\d+)?):/)?.[1];
          if (source && locations.size < 30) locations.add(source);
        }
      };
      child.stdout.on('data', record);
      child.stderr.on('data', record);
      const [code] = await once(child, 'exit');
      console.log(JSON.stringify({ target, exit: code, ...outcomes,
        ...(code !== 0 ? { failures: [...failures], locations: [...locations], categories: [...categories] } : {}),
      }));
      assert.equal(code, 0, `Required ${target} failed; sensitive test diagnostics suppressed`);
      assert(outcomes.packages > 0 && outcomes.tests > 0, 'Integration suite produced no test evidence');
      assert.equal(outcomes.skipped, 0, 'Required integration suite skipped a test');
    }
  } finally { await services.close(); }
}

export async function startPortalHarness({ admin = false } = {}) {
  assert.equal(typeof admin, 'boolean', 'Admin harness mode must be explicit');
  let apiBinary = resolve(backend, 'bin/identity-api');
  let fixtureBinary = resolve(backend, 'bin/portal-fixture');
  let notifierBinary = resolve(backend, 'bin/deletion-notifier');
  let signerBinary = resolve(backend, 'bin/audit-signer');
  let publisherBinary = resolve(backend, 'bin/admin-audit-publisher');
  let legalBinary = resolve(backend, 'bin/admin-legal');
  await Promise.all([
    access(apiBinary),
    access(fixtureBinary),
    access(notifierBinary),
    ...(admin ? [access(signerBinary), access(publisherBinary), access(legalBinary)] : []),
    access(resolve(workspace, 'apps/web/.next/BUILD_ID')),
  ]).catch(() => {
    throw new Error(
      'Build web, identity-api, fixture, deletion-notifier, and (for admin mode) audit-signer/admin-audit-publisher/admin-legal before this suite'
    );
  });

  const cleanup = [];
  const children = [];
  const responseCounts = new Map();
  const secrets = [];
  const routeReferences = new Set();
  const legalReferences = { accounts: new Set(), holds: new Set() };
  const legalSecrets = new Set();
  const rememberLegal = (value) => {
    const values = fixtureSecretValues(value);
    if (value?.metadata) values.push(...Object.values(value.metadata));
    for (const item of value?.items || []) if (typeof item.scope === 'string') values.push(item.scope);
    for (const item of values) legalSecrets.add(item);
    secrets.push(...values);
  };
  const close = portalCleanup(cleanup);
  const diagnostics = () => {
    console.error('Public API response counts:', redactFixtureSecrets(JSON.stringify(Object.fromEntries(responseCounts)), secrets));
    for (const { label, child, output } of children) {
      // Unknown server errors can include narratives, SQL parameters or headers
      // that no fixture-secret allowlist can predict. Never print child output.
      const entries = output.join('').split('\n').flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
      const errors = entries.filter((entry) => entry.level === 'ERROR').map((entry) => typeof entry.error === 'string' ? entry.error : '').join('\n');
      const categories = failureCategories(errors);
      console.error(JSON.stringify({ process: label, exit: child.exitCode, signal: child.signalCode, categories }));
    }
  };
  const start = (label, command, args, env, cwd = workspace) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...cleanEnvironment(), ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const output = [];
    const record = (chunk) => {
      output.push(String(chunk));
      while (output.join('').length > 65_536) output.shift();
    };
    child.stdout.on('data', record);
    child.stderr.on('data', record);
    child.on('error', (error) => record(`process error: ${error.code}`));
    children.push({ label, child, output });
    cleanup.push(async () => {
      if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
      const exit = once(child, 'exit').catch(() => {});
      child.kill('SIGTERM');
      await Promise.race([exit, delay(10_000, undefined, { ref: false })]);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await Promise.race([exit, delay(10_000, undefined, { ref: false })]);
      }
      assert(child.exitCode !== null || child.signalCode !== null, 'A disposable portal process did not stop');
    });
    return child;
  };

  try {
    if (process.platform === 'win32') {
      // Existing Nx Go targets intentionally use extensionless Linux artifact
      // names. Windows CreateProcess needs .exe; do not rename shared build output.
      const parent = resolve(tmpdir(), 'kilo');
      await mkdir(parent, { recursive: true });
      const temporary = await mkdtemp(resolve(parent, 'portal-browser-binaries-'));
      cleanup.push(() => rm(temporary, { recursive: true, force: true }));
      const apiExecutable = resolve(temporary, 'identity-api.exe');
      const fixtureExecutable = resolve(temporary, 'portal-fixture.exe');
      const notifierExecutable = resolve(temporary, 'deletion-notifier.exe');
      const signerExecutable = resolve(temporary, 'audit-signer.exe');
      const publisherExecutable = resolve(temporary, 'admin-audit-publisher.exe');
      const legalExecutable = resolve(temporary, 'admin-legal.exe');
      await Promise.all([copyFile(apiBinary, apiExecutable), copyFile(fixtureBinary, fixtureExecutable), copyFile(notifierBinary, notifierExecutable),
        ...(admin ? [copyFile(signerBinary, signerExecutable), copyFile(publisherBinary, publisherExecutable), copyFile(legalBinary, legalExecutable)] : [])]);
      apiBinary = apiExecutable;
      fixtureBinary = fixtureExecutable;
      notifierBinary = notifierExecutable;
      signerBinary = signerExecutable;
      publisherBinary = publisherExecutable;
      legalBinary = legalExecutable;
    }
    const services = await startPortalServices();
    cleanup.push(services.close);
    const { runID } = services;
    const storeEnv = {
      ...services.environment,
      AUDIT_STREAM_NAME: `PORTAL_BROWSER_AUDIT_${runID}`,
      ENVELOPE_MASTER_KEK: randomBytes(32).toString('base64'),
      ENVELOPE_MASTER_KEK_VERSION: '1',
      ENVELOPE_BLIND_INDEX_PEPPER: randomBytes(32).toString('base64'),
    };
    secrets.push(...secretEnvironmentValues(storeEnv));
    secrets.push(...fixtureSecretValues({ database_url: storeEnv.DATABASE_URL }));
    const fixture = (action, input = {}) => {
      secrets.push(...fixtureSecretValues(input));
      for (const value of fixtureRouteReferences(input)) routeReferences.add(value);
      const result = spawnSync(fixtureBinary, [action], {
        cwd: backend,
        env: {
          ...cleanEnvironment(),
          ...storeEnv,
          APP_ENV: 'test',
          PORTAL_FIXTURE_ALLOW: '1',
          PORTAL_FIXTURE_RUN_ID: runID,
          PORTAL_FIXTURE_ADMIN: admin ? '1' : '0',
        },
        input: JSON.stringify(input),
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 128 * 1024,
        windowsHide: true,
      });
      if (result.error || result.status !== 0) console.error(JSON.stringify({
        process: 'Owned portal fixture', exit: result.status, categories: failureCategories(result.stderr),
      }));
      assert(!result.error && result.status === 0,
        `Test-only fixture ${action} failed: ${result.error?.code || `exit ${result.status}`}`);
      let value;
      try {
        value = JSON.parse(result.stdout);
      } catch {
        throw new Error(`Test-only fixture ${action} did not return bounded JSON`);
      }
      secrets.push(...fixtureSecretValues(value));
      for (const reference of fixtureRouteReferences(value)) routeReferences.add(reference);
      if (action.startsWith('admin-legal-')) {
        rememberLegal(value);
        const remember = (object) => {
          if (!object || typeof object !== 'object') return;
          for (const [key, item] of Object.entries(object)) {
            if (/(?:^|_)account_ref$/.test(key) && canonicalUUID(item)) legalReferences.accounts.add(item);
            else if (key === 'hold_id' && canonicalUUID(item)) legalReferences.holds.add(item);
            else remember(item);
          }
        };
        remember(value);
      }
      return value;
    };
    const waitForNoticeCleanup = async (userID, accepted) => {
      let state;
      await waitFor(() => {
        state = fixture('deletion-state', { user_id: userID });
        return state.accepted === accepted && state.payloads === 0;
      }, 'relay acceptance bookkeeping and ciphertext cleanup', 15_000);
      return state;
    };
    fixture('migrate');
    const adminPolicy = admin ? fixture('admin-policy') : undefined;
    const tls = fixture('tls');
    secrets.push(tls.key);
    const tlsSPKI = createHash('sha256')
      .update(new X509Certificate(tls.cert).publicKey.export({ type: 'spki', format: 'der' }))
      .digest('base64');
    const apiPorts = [await freePort(), await freePort()];
    const nextPort = await freePort();
    let sequence = 0;
    const routeEvidence = new Map();
    const originEvidence = { unsafe: 0, anonymous: 0, mismatched: 0, referrers: 0, admin: 0, legal: 0 };
    const captures = new Map();
    // Observe the real upstream body before Chromium discards a completed,
    // cancelled fetch. Nothing is replayed, changed, or written to an artifact.
    const captureJSON = (path, method, status) => {
      const key = `${method} ${path}`;
      const adminRead = admin && ((method === 'GET' && [
        '/api/v1/admin/users', '/api/v1/admin/audit-logs', '/api/v1/admin/audit-logs/verify', '/api/v1/admin/ledger/verify', '/api/v1/admin/legal-holds',
      ].includes(path)) || (method === 'GET' && /^\/api\/v1\/admin\/users\/[0-9a-f-]{36}$/.test(path)) ||
        (method === 'POST' && ['/api/v1/admin/users/lookup', '/api/v1/admin/legal-inquiry/lookup',
          '/api/v1/admin/legal-holds', '/api/v1/admin/preservation-requests'].includes(path)) ||
        (method === 'DELETE' && /^\/api\/v1\/admin\/legal-holds\/[0-9a-f-]{36}$/.test(path) && status === 503));
      assert(adminRead || [
        'POST /api/v1/auth/recovery-codes/generate',
        'POST /api/v1/auth/webauthn/register/verify',
        'POST /api/v1/auth/stepup/verify',
        'POST /api/v1/auth/deletion/reclaim/options',
        'POST /api/v1/auth/deletion/reclaim/',
      ].includes(key), 'Unsupported response capture');
      assert(!captures.has(key), 'Response capture already armed');
      let timer;
      let finish;
      let settled = false;
      const promise = new Promise((resolve, reject) => {
        finish = (error, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          captures.delete(key);
          if (error) reject(new Error('Bounded upstream response capture failed'));
          else resolve(value);
        };
      });
      void promise.catch(() => {});
      timer = setTimeout(() => finish(true), 20_000);
      timer.unref();
      captures.set(key, { status, finish, limit: portalResponseBudget(path, method) });
      return promise;
    };
    cleanup.push(() => {
      for (const capture of captures.values()) capture.finish(true);
    });
    let origin;
    const ingress = httpsServer({ ...tls, minVersion: 'TLSv1.2' }, (request, response) => {
      if (!origin || request.headers.host !== new URL(origin).host) {
        response.writeHead(421).end();
        return;
      }
      const path = new URL(request.url, origin).pathname;
      const api = path === '/api' || path.startsWith('/api/');
      if (path.startsWith('/api/v1/admin/') && request.headers.dpop) {
        originEvidence.admin++;
        if (/^\/api\/v1\/admin\/(?:legal-holds(?:\/[^/]+)?|preservation-requests|legal-inquiry\/lookup)$/.test(path))
          originEvidence.legal++;
        // Chromium omits Origin on same-origin GETs. When present it must be
        // exact; unsafe requests below always require it, matching the real API.
        if (request.headers.origin && request.headers.origin !== origin) originEvidence.mismatched++;
        if (request.headers.referer) originEvidence.referrers++;
      }
      if (api && (request.headers.dpop || anonymousReclaim(path, request.method)) && !['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        originEvidence.unsafe++;
        if (anonymousReclaim(path, request.method)) originEvidence.anonymous++;
        if (request.headers.origin !== origin) originEvidence.mismatched++;
        if (request.headers.referer) originEvidence.referrers++;
      }
      const replica = replicaFor(path, sequence++);
      const upstream = httpRequest(
        {
          hostname: '127.0.0.1',
          port: api ? apiPorts[replica] : nextPort,
          method: request.method,
          path: request.url,
          headers: {
            ...request.headers,
            host: new URL(origin).host,
            'x-forwarded-for': request.socket.remoteAddress,
            'x-forwarded-proto': 'https',
            'x-forwarded-host': new URL(origin).host,
          },
          timeout: 15_000,
        },
        (result) => {
          if (api) {
            const summary = `${request.method} ${portalRoute(path)} ${result.statusCode}`;
            responseCounts.set(summary, (responseCounts.get(summary) || 0) + 1);
          }
          const key = `${request.method} ${path}`;
          const capture = captures.get(key);
          if (capture && result.statusCode === capture.status) {
            void capturePortalJSON(result, capture.limit).then((value) => {
              if (['/api/v1/admin/legal-holds', '/api/v1/admin/preservation-requests', '/api/v1/admin/legal-inquiry/lookup'].includes(path))
                rememberLegal(value);
              if (path === '/api/v1/admin/legal-holds' || path === '/api/v1/admin/preservation-requests') {
                for (const hold of value.items || [value.hold || value])
                  if (canonicalUUID(hold.id)) legalReferences.holds.add(hold.id);
              }
              capture.finish(false, value);
            }, () => capture.finish(true));
          }
          if (api && result.statusCode >= 200 && result.statusCode < 300) {
            const key = `${request.method} ${portalRoute(path)}`;
            const hits = routeEvidence.get(key) || [0, 0];
            hits[replica]++;
            routeEvidence.set(key, hits);
          }
          response.writeHead(result.statusCode, result.headers);
          result.pipe(response);
        }
      );
      upstream.on('timeout', () => upstream.destroy());
      upstream.on('error', () => {
        if (!response.headersSent)
          response.writeHead(502, { 'Cache-Control': 'private, no-store' });
        response.end();
      });
      request.on('aborted', () => upstream.destroy());
      request.pipe(upstream);
    });
    ingress.listen(0, '127.0.0.1');
    await once(ingress, 'listening');
    cleanup.push(
      () =>
        new Promise((resolve, reject) => {
          ingress.close((error) => error ? reject(error) : resolve());
          ingress.closeAllConnections();
        })
    );
    origin = `https://localhost:${ingress.address().port}`;
    assertLocalOrigin(origin);
    const mailParent = resolve(tmpdir(), 'kilo');
    await mkdir(mailParent, { recursive: true });
    const temporary = await mkdtemp(resolve(mailParent, 'portal-browser-mail-'));
    cleanup.push(() => rm(temporary, { recursive: true, force: true }));
    const caBundle = resolve(temporary, 'ca.pem');
    // Only the ephemeral public CA is written. Mail, bearer tokens, credentials,
    // private TLS keys, and browser traces never become filesystem artifacts.
    await writeFile(caBundle, tls.ca, { mode: 0o600 });
    const smtpUsername = randomBytes(24).toString('hex');
    const smtpPassword = randomBytes(32).toString('hex');
    const smtpFrom = `notices@${runID}.example.test`;
    secrets.push(smtpUsername, smtpPassword);
    const mail = await startMailSink({
      ...tls, username: smtpUsername, password: smtpPassword, from: smtpFrom,
      runID, origin, onSecrets: (values) => secrets.push(...values),
    });
    cleanup.push(() => mail.close());
    const workerDatabase = fixture('notifier-role');
    const notifierEnvironment = {
      ...storeEnv,
      DATABASE_URL: '',
      APP_ENV: admin ? 'test' : 'production',
      DELETION_NOTIFIER_DATABASE_URL: workerDatabase.database_url,
      DELETION_SMTP_HOST: '127.0.0.1',
      DELETION_SMTP_PORT: String(mail.port),
      DELETION_SMTP_TLS_MODE: 'implicit',
      DELETION_SMTP_USERNAME: smtpUsername,
      DELETION_SMTP_PASSWORD: smtpPassword,
      DELETION_SMTP_FROM: smtpFrom,
      DELETION_SMTP_PUBLIC_ORIGIN: origin,
      DELETION_SMTP_CA_BUNDLE: caBundle,
      DELETION_SMTP_TIMEOUT: '2s',
      DELETION_NOTIFIER_POLL_INTERVAL: '1s',
      DELETION_NOTIFIER_RETRY_BASE: '1s',
      DELETION_NOTIFIER_RETRY_MAX: '2s',
      GDPR_GRACE_PERIOD: '720h',
    };
    secrets.push(...secretEnvironmentValues(notifierEnvironment));
    let notifier;
    const startNotifier = () => {
      assert(!notifier || notifier.exitCode !== null || notifier.signalCode !== null,
        'A notifier process is already running');
      notifier = start('Deletion notifier', notifierBinary, ['run'], notifierEnvironment, backend);
    };
    const stopNotifier = async () => {
      if (!notifier || notifier.exitCode !== null || notifier.signalCode !== null) return;
      const exited = once(notifier, 'exit');
      notifier.kill('SIGTERM');
      await Promise.race([exited, delay(10_000, undefined, { ref: false }).then(() => { throw new Error('Notifier did not stop'); })]);
    };
    const signingKey = () =>
      generateKeyPairSync('ec', { namedCurve: 'P-256' })
        .privateKey.export({ type: 'pkcs8', format: 'pem' })
        .toString();
    const apiEnvironment = {
      ...storeEnv,
      APP_ENV: 'production',
      HOST: '127.0.0.1',
      PORTAL_ORIGIN: origin,
      OIDC_ISSUER: origin,
      OIDC_SIGNING_KEY_ACTIVE_PEM: signingKey(),
      OIDC_SIGNING_KEY_NEXT_PEM: signingKey(),
      OIDC_CLIENTS_JSON: JSON.stringify([
        {
          client_id: 'portal-browser-fixture',
          redirect_uris: [`${origin}/callback`],
          token_endpoint_auth_method: 'none',
          allowed_scopes: ['openid', 'profile'],
        },
      ]),
      WEBAUTHN_RP_ID: 'localhost',
      WEBAUTHN_RP_ORIGINS: origin,
      WEBAUTHN_RP_DISPLAY_NAME: 'Portal Browser Test',
      WEBAUTHN_USER_VERIFICATION: 'required',
      WEBAUTHN_RESIDENT_KEY: 'required',
      WEBAUTHN_MOCK_CHALLENGE_KEY: randomBytes(32).toString('base64'),
      STEPUP_REPLAY_HMAC_KEY: randomBytes(32).toString('base64'),
      SMS_GATEWAY_API_KEY: randomBytes(32).toString('hex'),
      SESSION_COOKIE_NAME: '__Host-session',
      SESSION_COOKIE_SECURE: 'true',
      SESSION_ABSOLUTE_TTL: '2h',
      SESSION_IDLE_TTL: '30m',
      TRUSTED_PROXY_CIDRS: '127.0.0.1/32',
      ADMIN_ENABLED: 'false',
      LEGAL_WORKFLOW_ENABLED: 'false',
      GRPC_ENABLED: 'false',
      GDPR_DELETION_ENABLED: 'true',
      GDPR_GRACE_PERIOD: '720h',
      ...(admin ? {
        APP_ENV: 'test', ADMIN_ENABLED: 'true',
        ADMIN_GOVERNANCE_POLICY_ID: adminPolicy.policy_id,
        ADMIN_ALLOWED_ORIGINS: origin, ADMIN_CONTEXT_RETENTION: '1h', ADMIN_LEGAL_RELEASED_RETENTION: '1h',
        ADMIN_PAGE_SIZE_DEFAULT: '5', ADMIN_PAGE_SIZE_MAX: '20', ADMIN_CHAIN_VERIFY_MAX_LIMIT: '5',
        STEPUP_TOKEN_TTL: '20s',
      } : {}),
    };
    secrets.push(...secretEnvironmentValues(apiEnvironment));
    let lookupFixture;
    let signer;
    if (admin) {
      const auditEnvironment = { ...apiEnvironment, PORT: '8080', AUDIT_BATCH_SIZE: '20', AUDIT_FLUSH_INTERVAL: '1s' };
      signer = start('Audit signer', signerBinary, [], auditEnvironment, backend);
      start('Admin audit publisher', publisherBinary, [], auditEnvironment, backend);
      // stdout includes a synthetic identity and fixture ID. Parse in bounded
      // process-local memory, never send it to child diagnostics or artifacts.
      lookupFixture = lookupProbeFixture(spawnSync(legalBinary, ['--operation=lookup-probe'], {
        cwd: backend, env: { ...cleanEnvironment(), ...auditEnvironment }, encoding: 'utf8',
        timeout: 60_000, maxBuffer: 64 * 1024, windowsHide: true,
      }));
      secrets.push(lookupFixture);
      const verification = fixture('admin-legal-probe', { fixture_id: lookupFixture });
      assert(verification.verified && verification.account_deleted && verification.missing_rejected &&
        verification.wrong_rejected && verification.mismatched_key_rejected, 'Real lookup prerequisite checks failed');
      apiEnvironment.ADMIN_LOOKUP_FIXTURE_ID = lookupFixture;
      // The production binary must fail closed with a mismatching fixture, not
      // merely return false from a fake LookupEnabled dependency.
      const rejected = spawnSync(apiBinary, [], {
        cwd: backend, env: { ...cleanEnvironment(), ...apiEnvironment, PORT: String(apiPorts[0]), ADMIN_LOOKUP_FIXTURE_ID: randomUUID() },
        encoding: 'utf8', timeout: 15_000, maxBuffer: 64 * 1024, windowsHide: true,
      });
      assert(!rejected.error && rejected.status !== null && rejected.status !== 0,
        'API accepted an unverified signer fixture or failed to stop');
    }
    const apiChildren = [];
    const startAPIs = () => {
      for (const [index, port] of apiPorts.entries()) {
        apiChildren[index] = start(
          `API replica ${index + 1}`,
          apiBinary,
          [],
          { ...apiEnvironment, PORT: String(port) },
          backend
        );
      }
    };
    startAPIs();
    startNotifier();
    start(
      'Next production',
      process.execPath,
      [
        resolve(workspace, 'node_modules/next/dist/bin/next'),
        'start',
        '--hostname',
        '127.0.0.1',
        '--port',
        String(nextPort),
      ],
      { NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1' },
      resolve(workspace, 'apps/web')
    );
    for (const [label, port, path] of [
      ['API A', apiPorts[0], '/healthz'],
      ['API B', apiPorts[1], '/healthz'],
      ['production Next', nextPort, '/login'],
    ]) {
      await waitFor(async () => {
        assert(
          children.every(({ child }) => child.exitCode === null),
          'A portal server exited during startup'
        );
        try {
          const result = await fetch(`http://127.0.0.1:${port}${path}`, {
            signal: AbortSignal.timeout(1000),
            redirect: 'error',
          });
          await result.arrayBuffer();
          return result.ok;
        } catch {
          return false;
        }
      }, label);
    }
    const retired = new Set();
    const assertHealthy = () => assert(children.every(({ child }) => retired.has(child) ||
      (child.exitCode === null && child.signalCode === null)), 'A supervised portal process exited');
    const stopSignerForDestructiveFixtures = async () => {
      assert(admin && signer && !retired.has(signer), 'No live owned signer to retire');
      assertHealthy();
      const exited = once(signer, 'exit');
      assert(signer.kill('SIGTERM'), 'Owned signer did not accept graceful shutdown');
      const [code, signal] = await Promise.race([exited,
        delay(10_000, undefined, { ref: false }).then(() => { throw new Error('Owned signer did not stop'); })]);
      assert(code === 0 && signal === null, 'Owned signer did not exit cleanly');
      retired.add(signer);
    };
    const setLegalLookup = async (enabled) => {
      assert(admin && typeof enabled === 'boolean' && canonicalUUID(lookupFixture), 'Invalid owned legal startup scenario');
      for (const child of apiChildren) {
        retired.add(child);
        const exited = once(child, 'exit');
        child.kill('SIGTERM');
        await Promise.race([exited, delay(10_000, undefined, { ref: false }).then(() => { throw new Error('Owned API did not stop'); })]);
      }
      if (enabled) apiEnvironment.ADMIN_LOOKUP_FIXTURE_ID = lookupFixture;
      else delete apiEnvironment.ADMIN_LOOKUP_FIXTURE_ID;
      startAPIs();
      for (const port of apiPorts) await waitFor(async () => {
        assertHealthy();
        try {
          const response = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1000), redirect: 'error' });
          await response.arrayBuffer();
          return response.ok;
        } catch { return false; }
      }, 'owned legal API configuration');
    };
    const assertPrivateLogs = () => {
      for (const { label, output } of children) {
        const summary = privateLogSummary(output.join(''), secrets);
        if (summary.matches) console.error(JSON.stringify({ check: 'supervised-log-privacy', process: label, ...summary }));
        assert(summary.matches === 0, 'Private fixture material entered supervised process logs');
      }
    };
    const waitForAdminDelivery = async () => {
      assert(admin, 'Admin delivery requires explicit harness mode');
      let state;
      await waitFor(() => {
        assertHealthy();
        state = fixture('admin-delivery');
        return state.pending === 0 && state.signed > 0;
      }, 'real admin outbox delivery and canonical-v2 signing', 30_000);
      return state;
    };
    return { runID, origin, tlsSPKI, fixture, mail, captureJSON, startNotifier, stopNotifier, waitForNoticeCleanup, waitForAdminDelivery, assertHealthy, assertPrivateLogs, setLegalLookup, stopSignerForDestructiveFixtures, routeEvidence, originEvidence, close, diagnostics, secrets, routeReferences, legalReferences, legalSecrets };
  } catch (error) {
    try { diagnostics(); } finally { await close(); }
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3 || process.argv[2] !== '--integration') {
    console.error('Usage: portal-harness.mjs --integration');
    process.exitCode = 1;
  } else {
    try { await runPortalIntegrationSuites(); }
    catch (error) { console.error(browserFailure(error, 'serial-integration')); process.exitCode = 1; }
  }
}
