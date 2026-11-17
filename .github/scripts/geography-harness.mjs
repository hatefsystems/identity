import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:https';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { acceptanceLifecycle, assertLocalOrigin, freePorts, portalCleanup, startPortalServices } from './portal-harness.mjs';
import { acceptanceIdentity, assertIdentity } from './acceptance-report.mjs';
import { createFixtureTLS, registrationForwardHeaders } from './registration-browser.mjs';
import { assertNoProductionGeographyFixture, createDisposableGeographyApp, geographyFixtureRoute, syntheticGeography, writeSyntheticSnapshot } from './geography-fixture.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const backend = resolve(workspace, 'apps/identity-api');
export const geographyIngressPaths = Object.freeze(['/api/v1/geography/provinces', '/api/v1/geography/localities']);

export function geographyReadRoute(method, path) {
  if (method !== 'GET' || typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#]/.test(path)) return false;
  const pathname = path.split('?', 1)[0];
  return geographyIngressPaths.includes(pathname) || /^\/api\/v1\/geography\/places\/[1-9][0-9]{0,18}$/.test(pathname);
}

export function geographyEnvironment(extra = {}) {
  const safe = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(?:PATH|HOME|TMP|TEMP|LANG|LC_ALL)$/i.test(key)));
  return { ...safe, GOTOOLCHAIN: 'local', NX_DAEMON: 'false', NX_ISOLATE_PLUGINS: 'false', CI: 'true', NEXT_TELEMETRY_DISABLED: '1', ...extra };
}

export function geographyOperatorEnvironment(kind, databaseURL) {
  assert(['check', 'import', 'migrate'].includes(kind), 'Unknown geography operator');
  const database = new URL(databaseURL);
  assert(database.protocol === 'postgres:' && database.hostname === '127.0.0.1' && database.port &&
    /^\/portal_browser_[a-f0-9]{32}$/.test(database.pathname), 'Geography operator requires its owned database');
  return geographyEnvironment({ [kind === 'migrate' ? 'DATABASE_URL' : `GEOGRAPHY_${kind.toUpperCase()}_DATABASE_URL`]: databaseURL });
}

export function geographyRoleSQL(database, readerPassword, importerPassword) {
  assert(/^portal_browser_[a-f0-9]{32}$/.test(database) && [readerPassword, importerPassword].every((value) => /^[a-f0-9]{48}$/.test(value)), 'Geography role provisioning requires owned synthetic credentials');
  return `CREATE ROLE geography_reader LOGIN NOINHERIT PASSWORD '${readerPassword}';
CREATE ROLE geography_importer LOGIN NOINHERIT PASSWORD '${importerPassword}';
GRANT CONNECT ON DATABASE ${database} TO geography_reader, geography_importer;
GRANT USAGE ON SCHEMA public TO geography_reader, geography_importer;
GRANT SELECT ON geography_catalogs, geography_types, geography_places, geography_place_versions, geography_catalog_state TO geography_reader, geography_importer;
GRANT INSERT (revision,country,source_release,cities_sha256,types_sha256,cities_bytes,types_bytes,place_count,type_count,province_count,importer_version,normalization_version) ON geography_catalogs TO geography_importer;
GRANT INSERT ON geography_types, geography_places, geography_place_versions TO geography_importer;
GRANT UPDATE (last_seen_revision) ON geography_places TO geography_importer;
GRANT UPDATE (active_revision) ON geography_catalog_state TO geography_importer;`;
}

async function waitFor(check, lifecycle) {
  const deadline = Math.min(Date.now() + 60_000, lifecycle.deadline - 120_000);
  while (Date.now() < deadline) {
    lifecycle.check();
    if (await check()) return;
    await delay(100, undefined, { signal: lifecycle.signal });
  }
  throw new Error('Owned geography service readiness failed');
}

export function superviseGeographyProcess(command, args, { cwd = workspace, env = geographyEnvironment(), lifecycle, resources, finite = false, input } = {}) {
  lifecycle.check();
  const child = spawn(command, args, { cwd, env, detached: true, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
  if (input !== undefined) { child.stdin.on('error', () => {}); child.stdin.end(input); }
  let stdout = '', stderr = '', overflow = false, failure;
  const capture = (stream, chunk) => {
    if (stream === 'stdout') stdout += chunk; else stderr += chunk;
    if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 128 * 1024) {
      stdout = stderr = ''; overflow = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Startup error has no process group. */ }
    }
  };
  child.stdout.on('data', (chunk) => capture('stdout', chunk));
  child.stderr.on('data', (chunk) => capture('stderr', chunk));
  child.once('error', () => { failure = true; });
  const exited = new Promise((done) => child.once('close', (code, signal) => done({ code, signal })));
  const alive = () => {
    if (!child.pid) return false;
    try { process.kill(-child.pid, 0); return true; }
    catch (error) { assert.equal(error.code, 'ESRCH', 'Cannot inspect owned geography process group'); return false; }
  };
  const close = async () => {
    if (alive()) process.kill(-child.pid, 'SIGTERM');
    const stopped = Date.now() + 10_000;
    while (alive() && Date.now() < stopped) await delay(50);
    if (alive()) process.kill(-child.pid, 'SIGKILL');
    const killed = Date.now() + 10_000;
    while (alive() && Date.now() < killed) await delay(50);
    assert(!alive(), 'Owned geography process tree did not stop');
    await exited;
  };
  resources.push(close);
  const aborted = () => { if (child.pid && alive()) process.kill(-child.pid, 'SIGTERM'); };
  lifecycle.signal.addEventListener('abort', aborted, { once: true });
  child.once('close', () => lifecycle.signal.removeEventListener('abort', aborted));
  return {
    child,
    assertHealthy() { assert(!failure && !overflow && child.exitCode === null && child.signalCode === null, 'Owned geography process exited'); },
    assertPrivate(labels) { assert(!overflow && !labels.some((value) => value && (stdout.includes(value) || stderr.includes(value))), 'Geography private value entered process output'); },
    async result() {
      assert(finite, 'Long-lived service cannot produce completed build evidence');
      const result = await exited;
      lifecycle.check();
      assert(!failure && !overflow && result.code === 0 && result.signal === null, 'Owned geography command failed; diagnostics suppressed');
      assert(!alive(), 'Completed geography command left descendants');
      return stdout;
    },
  };
}

export async function startGeographyHarness({ identify = acceptanceIdentity } = {}) {
  const lifecycle = acceptanceLifecycle();
  const resources = [], processes = [], disposers = portalCleanup(resources);
  let identity;
  let closing;
  const close = () => closing ||= Promise.resolve().then(async () => {
    lifecycle.beginTeardown();
    try {
      const result = await disposers();
      lifecycle.check(true); lifecycle.signal.throwIfAborted();
      assertIdentity(await identify(), identity);
      return result;
    } finally { lifecycle.release(); }
  });
  const run = async (command, args, env, cwd, input) => {
    const process = superviseGeographyProcess(command, args, { lifecycle, resources, finite: true, env, cwd, input });
    processes.push(process);
    return process.result();
  };
  try {
    identity = await identify();
    await assertNoProductionGeographyFixture();
    await mkdir('/tmp/kilo', { recursive: true });
    const temporary = await mkdtemp('/tmp/kilo/geography-browser-');
    resources.push(() => rm(temporary, { recursive: true, force: true }));
    const app = await createDisposableGeographyApp(temporary);
    const binaries = {};
    const nx = createRequire(resolve(workspace, 'package.json')).resolve('nx/bin/nx.js');
    for (const [name, source] of [['api', 'server'], ['migrate', 'migrate'], ['geography', 'geography']]) {
      const path = resolve(temporary, name);
      await run(process.execPath, [nx, 'exec', '-p', 'schemas', '--', 'go', '-C', backend, 'build', '-o', path, `./cmd/${source}`]);
      binaries[name] = { path, sha256: createHash('sha256').update(await readFile(path)).digest('hex') };
    }
    await run(process.execPath, [nx, 'exec', '-p', 'schemas', '--', process.execPath,
      resolve(workspace, 'node_modules/next/dist/bin/next'), 'build', app, '--webpack']);
    await access(resolve(app, '.next/BUILD_ID'));
    const services = await startPortalServices({ lifecycle });
    resources.push(services.close);
    const ownerURL = services.environment.DATABASE_URL;
    await run(binaries.migrate.path, ['up'], geographyOperatorEnvironment('migrate', ownerURL), backend);
    const owner = new URL(ownerURL);
    const readerPassword = randomBytes(24).toString('hex'), importerPassword = randomBytes(24).toString('hex');
    const roleURL = (role, password) => { const url = new URL(ownerURL); url.username = role; url.password = password; return url.href; };
    const readerURL = roleURL('geography_reader', readerPassword), importerURL = roleURL('geography_importer', importerPassword);
    const sql = geographyRoleSQL(owner.pathname.slice(1), readerPassword, importerPassword);
    await run('psql', ['-X', '-v', 'ON_ERROR_STOP=1', '-h', owner.hostname, '-p', owner.port, '-U', owner.username,
      '-d', owner.pathname.slice(1)], geographyEnvironment({ PGPASSWORD: decodeURIComponent(owner.password) }), workspace, sql);
    let revision = null;
    const importSnapshot = async (changed = false) => {
      const paths = await writeSyntheticSnapshot(temporary, revision, changed);
      const args = [`--cities=${paths.cities}`, `--types=${paths.types}`, `--manifest=${paths.manifest}`];
      const plan = JSON.parse(await run(binaries.geography.path, ['check', ...args], geographyOperatorEnvironment('check', readerURL), backend));
      assert(/^[0-9a-f]{64}$/.test(plan.plan_digest) && plan.retirements === 0, 'Synthetic geography check failed');
      await run(binaries.geography.path, ['import', ...args, `--apply-plan=${plan.plan_digest}`], geographyOperatorEnvironment('import', importerURL), backend);
      const result = await run('psql', ['-X', '-At', '-v', 'ON_ERROR_STOP=1', '-h', owner.hostname, '-p', owner.port,
        '-U', 'geography_reader', '-d', owner.pathname.slice(1), '-c', 'SELECT active_revision FROM geography_catalog_state'],
      geographyEnvironment({ PGPASSWORD: readerPassword }));
      const next = result.trim();
      assert(/^[1-9][0-9]{0,18}$/.test(next) && next !== revision, 'Synthetic geography import did not activate a new revision');
      revision = next;
      return next;
    };
    await importSnapshot();
    const [apiPort, nextPort] = await freePorts(2);
    const tls = createFixtureTLS(services.runID);
    const tlsCAPath = resolve(temporary, 'fixture-ca.pem');
    await writeFile(tlsCAPath, tls.ca, { mode: 0o600 });
    const tlsSPKI = createHash('sha256').update(new X509Certificate(tls.cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
    let origin, fault;
    const observed = { requests: 0, violations: 0, delayed: 0, injected: 0, real: 0, statuses: {}, endpoints: { provinces: 0, localities: 0, lookup: 0 } };
    const held = new Set();
    const ingress = createServer({ ...tls, minVersion: 'TLSv1.2' }, (request, response) => {
      if (!origin || request.headers.host !== new URL(origin).host) { response.writeHead(421).end(); return; }
      const path = request.url.split('?', 1)[0];
      const api = path.startsWith('/api/');
      if (api && !geographyReadRoute(request.method, request.url)) { observed.violations++; response.writeHead(404).end(); return; }
      if (api) {
        observed.requests++;
        if (request.headers.cookie || request.headers.dpop || request.headers['x-portal-session'] || request.headers.authorization) observed.violations++;
      }
      const activeFault = api && fault?.path === path ? fault : null;
      if (activeFault) fault = undefined;
      if (activeFault && activeFault.kind !== 'delay') {
        observed.injected++;
        response.writeHead(activeFault.kind === 'unavailable' ? 503 : 429, {
          'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Retry-After': '1',
        }).end(JSON.stringify({ error: activeFault.kind === 'unavailable' ? 'temporarily_unavailable' : 'rate_limited' }));
        return;
      }
      const upstream = httpRequest({ hostname: '127.0.0.1', port: api ? apiPort : nextPort,
        method: request.method, path: request.url, headers: registrationForwardHeaders(request.headers, origin), timeout: 10_000 }, (result) => {
        if (api) {
          observed.real++; observed.statuses[result.statusCode] = (observed.statuses[result.statusCode] || 0) + 1;
          const endpoint = path.endsWith('/provinces') ? 'provinces' : path.endsWith('/localities') ? 'localities' : 'lookup';
          observed.endpoints[endpoint]++;
        }
        if (activeFault?.kind === 'delay') {
          const chunks = []; let size = 0;
          result.on('data', (chunk) => { size += chunk.length; if (size <= 2 * 1024 * 1024) chunks.push(chunk); else result.destroy(); });
          result.once('end', () => {
            observed.delayed++;
            const release = () => { held.delete(release); response.writeHead(result.statusCode, result.headers).end(Buffer.concat(chunks)); chunks.length = 0; };
            held.add(release); activeFault.arrived(); activeFault.release = release;
          });
          result.once('error', () => { observed.violations++; response.destroy(); });
        } else { response.writeHead(result.statusCode, result.headers); result.pipe(response); }
      });
      upstream.on('timeout', () => upstream.destroy());
      upstream.once('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
      request.pipe(upstream);
    });
    ingress.listen(0, '127.0.0.1'); await once(ingress, 'listening');
    resources.push(() => new Promise((done, reject) => { for (const release of held) release();
      ingress.close((error) => error ? reject(error) : done()); ingress.closeAllConnections(); }));
    origin = `https://localhost:${ingress.address().port}`; assertLocalOrigin(origin);
    const signingKey = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const apiEnvironment = geographyEnvironment({ ...services.environment, DATABASE_URL: readerURL,
      APP_ENV: 'production', HOST: '127.0.0.1', PORT: String(apiPort), PORTAL_ORIGIN: origin, OIDC_ISSUER: origin,
      OIDC_SIGNING_KEY_ACTIVE_PEM: signingKey(), OIDC_SIGNING_KEY_NEXT_PEM: signingKey(),
      OIDC_CLIENTS_JSON: JSON.stringify([{ client_id: 'geography-browser', redirect_uris: [`${origin}/callback`], token_endpoint_auth_method: 'none', allowed_scopes: ['openid'] }]),
      ENVELOPE_MASTER_KEK: randomBytes(32).toString('base64'), ENVELOPE_MASTER_KEK_VERSION: '1',
      ENVELOPE_BLIND_INDEX_PEPPER: randomBytes(32).toString('base64'),
      WEBAUTHN_RP_ID: 'localhost', WEBAUTHN_RP_ORIGINS: origin, WEBAUTHN_RP_DISPLAY_NAME: 'Geography acceptance',
      WEBAUTHN_USER_VERIFICATION: 'required', WEBAUTHN_RESIDENT_KEY: 'required',
      WEBAUTHN_MOCK_CHALLENGE_KEY: randomBytes(32).toString('base64'), STEPUP_REPLAY_HMAC_KEY: randomBytes(32).toString('base64'),
      SESSION_COOKIE_NAME: '__Host-session', SESSION_COOKIE_SECURE: 'true', SESSION_ABSOLUTE_TTL: '2h', SESSION_IDLE_TTL: '30m',
      TRUSTED_PROXY_CIDRS: '127.0.0.1/32', SMS_ENABLED: 'false', REGISTRATION_ENABLED: 'false',
      ADMIN_ENABLED: 'false', LEGAL_WORKFLOW_ENABLED: 'false', GRPC_ENABLED: 'false', GDPR_DELETION_ENABLED: 'false',
    });
    const apiProcess = superviseGeographyProcess(binaries.api.path, [], { cwd: backend, env: apiEnvironment, lifecycle, resources });
    const nextProcess = superviseGeographyProcess(process.execPath, [resolve(workspace, 'node_modules/next/dist/bin/next'),
      'start', app, '--hostname', '127.0.0.1', '--port', String(nextPort)], { lifecycle, resources, env: geographyEnvironment({ NODE_ENV: 'production' }) });
    processes.push(apiProcess, nextProcess);
    for (const [port, path] of [[apiPort, '/healthz'], [nextPort, geographyFixtureRoute]]) await waitFor(async () => {
      apiProcess.assertHealthy(); nextProcess.assertHealthy();
      try { const response = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(1000), redirect: 'error' });
        await response.arrayBuffer(); return response.ok; } catch { return false; }
    }, lifecycle);
    return { origin, tlsSPKI, tlsCA: tls.ca, tlsCAPath, identity, observed, importSnapshot, close, lifecycle,
      arm(path, kind) {
        assert(geographyIngressPaths.includes(path) && ['delay', 'unavailable', 'rate-limited'].includes(kind) && !fault, 'Fault injection requires an explicit geography ingress route');
        let arrived, timer;
        const pending = new Promise((done, reject) => {
          const abort = () => reject(new Error('Owned geography response wait interrupted'));
          timer = setTimeout(() => { lifecycle.signal.removeEventListener('abort', abort); reject(new Error('Owned geography response did not arrive')); }, 20_000);
          lifecycle.signal.addEventListener('abort', abort, { once: true });
          arrived = () => { clearTimeout(timer); lifecycle.signal.removeEventListener('abort', abort); done(); };
          resources.push(() => { clearTimeout(timer); lifecycle.signal.removeEventListener('abort', abort); });
        });
        void pending.catch(() => {});
        const armed = { path, kind, arrived }; fault = armed;
        return { arrived: pending, release: () => { assert(armed.release, 'No completed real response to release'); armed.release(); } };
      },
      async assertClean() {
        assert.equal(observed.violations, 0, 'Geography browser violated anonymous read/privacy boundary');
        assert(!fault && held.size === 0, 'Geography harness left an armed/delayed fault');
        apiProcess.assertHealthy(); nextProcess.assertHealthy();
        const labels = [...syntheticGeography().cities.map((place) => place.Name), readerPassword, importerPassword,
          ...Object.entries(apiEnvironment).filter(([key, value]) => /PASSWORD|SECRET|PEPPER|KEK|KEY.*PEM|CHALLENGE_KEY|HMAC_KEY/.test(key) && value.length >= 16).map(([, value]) => value)];
        for (const process of processes) process.assertPrivate(labels);
        for (const binary of Object.values(binaries)) assert.equal(createHash('sha256').update(await readFile(binary.path)).digest('hex'), binary.sha256, 'Geography binary identity changed');
        assertIdentity(await identify(), identity);
      },
      binaryEvidence: Object.fromEntries(Object.entries(binaries).map(([name, value]) => [name, value.sha256])),
    };
  } catch (error) { await close(); throw error; }
}
