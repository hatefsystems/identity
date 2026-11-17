import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { acceptanceLifecycle, portalCleanup } from './portal-harness.mjs';
import { assertGeographyReport, geographyChecks, geographyJourneys, geographyLocaleChecks, geographyLocales, integrationPackages, integrationTargets, racePackages } from './acceptance-report.mjs';
import { expectedGeographyResourceFailure, geographyBounds, geographyNames, runGeographyBrowser } from './geography-browser.mjs';
import { geographyEnvironment, geographyIngressPaths, geographyOperatorEnvironment, geographyReadRoute, geographyRoleSQL, superviseGeographyProcess } from './geography-harness.mjs';
import { assertNoProductionGeographyFixture, createDisposableGeographyApp, geographyFixtureMarker, geographyFixtureRoute, syntheticGeography, writeSyntheticSnapshot } from './geography-fixture.mjs';

const identity = { revision: 'a'.repeat(40), source: 'b'.repeat(64), runId: '123', runAttempt: '1',
  generated: Object.fromEntries(['apps/identity-api/internal/db', 'libs/schemas/gen/go', 'libs/schemas/gen/ts'].map((path) => [path, { files: 1, sha256: 'c'.repeat(64) }])) };
const binaryEvidence = { api: 'd'.repeat(64), geography: 'e'.repeat(64), migrate: 'f'.repeat(64) };
const localeEvidence = (locale) => ({ locale, journeys: [...geographyJourneys], checks: [...geographyLocaleChecks],
  services: { requests: 7, real: 5, delayed: 1, injected: 2, violations: 0, statuses: { 200: 3, 409: 1, 429: 1 }, endpoints: { provinces: 2, localities: 2, lookup: 1 } } });
const fullReport = () => ({ schema: 1, kind: 'geography-browser', scope: 'full', status: 'passed', identity, binaryEvidence,
  cleanup: { completed: true }, exit: 0, failed: 0, skipped: 0, tests: geographyChecks.length, checks: [...geographyChecks],
  localeEvidence: geographyLocales.map(localeEvidence) });

async function temporary(t) {
  await mkdir('/tmp/kilo', { recursive: true });
  const directory = await mkdtemp('/tmp/kilo/geography-policy-');
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('geography fixture is a complete declared synthetic snapshot with real importer hashes and exact source shape', async (t) => {
  const directory = await temporary(t);
  const paths = await writeSyntheticSnapshot(directory);
  const manifest = JSON.parse(await readFile(paths.manifest));
  assert.deepEqual(Object.keys(manifest).sort(), ['cities_bytes', 'cities_sha256', 'complete_snapshot', 'country', 'expected_current_revision',
    'place_count', 'province_count', 'source_release', 'type_count', 'types_bytes', 'types_sha256'].sort());
  assert.equal(manifest.complete_snapshot, true); assert.equal(manifest.expected_current_revision, null);
  assert.equal(manifest.country, 'IR'); assert.equal(manifest.province_count, 2);
  const fixture = syntheticGeography();
  for (const name of ['cities', 'types']) {
    const bytes = await readFile(paths[name]);
    assert.equal(bytes.length, manifest[`${name}_bytes`]);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), manifest[`${name}_sha256`]);
    assert.deepEqual(JSON.parse(bytes), fixture[name]);
  }
  for (const place of fixture.cities) assert.deepEqual(Object.keys(place).sort(), ['CenterType', 'Id', 'Name', 'ParentId']);
  assert.equal(fixture.cities.filter((place) => place.CenterType === 2 && place.ParentId === null).length, 2);
  assert(fixture.cities.some((place) => place.CenterType === 5 && fixture.cities.find((parent) => parent.Id === place.ParentId)?.CenterType === 5));
  await writeSyntheticSnapshot(directory, '1', true);
  const changed = JSON.parse(await readFile(paths.manifest));
  assert.equal(changed.expected_current_revision, '1'); assert.equal(changed.place_count, manifest.place_count);
  assert.notEqual(changed.cities_sha256, manifest.cities_sha256);
});

test('disposable app copies only selector/provider/public style, never production routes, prior builds, env or real data', async (t) => {
  const directory = await temporary(t);
  const app = await createDisposableGeographyApp(directory);
  assert.deepEqual((await readdir(resolve(app, 'app'))).sort(), ['_components', '_lib', 'fonts', 'geography-acceptance', 'global.css', 'layout.tsx']);
  assert.deepEqual((await readdir(resolve(app, 'app/_components'))).sort(), ['location-selector.tsx', 'native-dialog.tsx']);
  assert.deepEqual(await readdir(resolve(app, 'app/_lib')), ['geography-client.ts']);
  for (const path of ['.next', '.env', 'data', 'app/dashboard', 'app/(auth)', 'app/admin']) await assert.rejects(access(resolve(app, path)));
  const page = await readFile(resolve(app, `app${geographyFixtureRoute}/page.tsx`), 'utf8');
  assert(page.includes(geographyFixtureMarker));
  assert.match(page, /<LocationSelector value=\{value\} onChange=\{setValue\}/);
  assert.match(page, /<DisplayProvider preferences=/);
  assert.doesNotMatch(page, /key=|GeographyClient|fetch\(|mock|initialItems/);
  await assert.rejects(createDisposableGeographyApp('/data/projects/identity/apps/web'), /run-owned temporary/);
  const source = await readFile(new URL('./geography-fixture.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /data\/cities|data\/types|process\.env.*(?:CITIES|TYPES)|copy.*\.env/);
});

test('fixture exclusion checks actual production route and compiled artifact bytes, not just filenames', async (t) => {
  const directory = await temporary(t);
  await mkdir(resolve(directory, 'app')); await mkdir(resolve(directory, '.next'));
  await writeFile(resolve(directory, 'app/page.tsx'), 'public-route'); await writeFile(resolve(directory, '.next/chunk.js'), 'public-build');
  await assertNoProductionGeographyFixture(directory);
  for (const path of ['app/page.tsx', '.next/chunk.js']) {
    await writeFile(resolve(directory, path), geographyFixtureMarker);
    await assert.rejects(assertNoProductionGeographyFixture(directory), /production routes\/artifacts/);
    await writeFile(resolve(directory, path), 'public');
  }
  await mkdir(resolve(directory, `app${geographyFixtureRoute}`));
  await assert.rejects(assertNoProductionGeographyFixture(directory), /production routes\/artifacts/);
});

test('geography subprocess environments never inherit shared DB/importer/session/proxy/key settings', (t) => {
  const keys = ['DATABASE_URL', 'GEOGRAPHY_IMPORT_DATABASE_URL', 'GEOGRAPHY_CHECK_DATABASE_URL', 'REDIS_URL', 'NATS_URL',
    'PGPASSWORD', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_OPTIONS', 'HTTP_PROXY', 'ENVELOPE_MASTER_KEK', 'GOTOOLCHAIN'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  for (const key of keys) process.env[key] = 'PRIVATE-INHERITED';
  t.after(() => { for (const [key, value] of Object.entries(previous)) if (value === undefined) delete process.env[key]; else process.env[key] = value; });
  const clean = geographyEnvironment();
  assert.equal(clean.GOTOOLCHAIN, 'local');
  for (const key of keys.filter((key) => key !== 'GOTOOLCHAIN')) assert.equal(clean[key], undefined);
  const url = `postgres://geography_importer:synthetic@127.0.0.1:43210/portal_browser_${'a'.repeat(32)}?sslmode=disable`;
  for (const mode of ['check', 'import', 'migrate']) {
    const env = geographyOperatorEnvironment(mode, url);
    const key = mode === 'migrate' ? 'DATABASE_URL' : `GEOGRAPHY_${mode.toUpperCase()}_DATABASE_URL`;
    assert.equal(env[key], url);
    for (const other of ['DATABASE_URL', 'GEOGRAPHY_IMPORT_DATABASE_URL', 'GEOGRAPHY_CHECK_DATABASE_URL'].filter((value) => value !== key)) assert.equal(env[other], undefined);
  }
  for (const invalid of [url.replace('127.0.0.1', 'remote.example.test'), url.replace('portal_browser_', 'identity_'), url.replace(':43210', '')])
    assert.throws(() => geographyOperatorEnvironment('import', invalid), /owned database/);
});

test('synthetic role grants are NOINHERIT non-owner and exact column capabilities without deletion, DDL or account access', () => {
  const sql = geographyRoleSQL(`portal_browser_${'a'.repeat(32)}`, 'b'.repeat(48), 'c'.repeat(48));
  assert.match(sql, /CREATE ROLE geography_reader LOGIN NOINHERIT/);
  assert.match(sql, /CREATE ROLE geography_importer LOGIN NOINHERIT/);
  assert.match(sql, /GRANT INSERT \(revision,country,source_release,cities_sha256,types_sha256,cities_bytes,types_bytes,place_count,type_count,province_count,importer_version,normalization_version\) ON geography_catalogs TO geography_importer/);
  assert.match(sql, /UPDATE \(last_seen_revision\) ON geography_places/);
  assert.match(sql, /UPDATE \(active_revision\) ON geography_catalog_state/);
  assert.doesNotMatch(sql, /SUPERUSER|CREATEDB|CREATEROLE|BYPASSRLS|GRANT ALL|DELETE|TRUNCATE|accounts|users|writing_tx|imported_at|OWNER|ON SCHEMA.*CREATE/);
  for (const args of [['shared_database', 'b'.repeat(48), 'c'.repeat(48)], [`portal_browser_${'a'.repeat(32)}`, "';DROP", 'c'.repeat(48)]]) assert.throws(() => geographyRoleSQL(...args));
  const source = new URL('./geography-harness.mjs', import.meta.url);
  return readFile(source, 'utf8').then((text) => {
    assert.match(text, /PGPASSWORD: decodeURIComponent\(owner.password\)/);
    assert.doesNotMatch(text, /'-c', sql|DATABASE_URL: importerURL|GEOGRAPHY_IMPORT_DATABASE_URL:.*apiEnvironment/);
  });
});

test('anonymous real ingress and fault injection are exact geography GET routes only', () => {
  for (const path of [...geographyIngressPaths, '/api/v1/geography/places/9223372036854775807']) {
    assert(geographyReadRoute('GET', path + '?country=IR'));
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT']) assert(!geographyReadRoute(method, path));
  }
  for (const path of ['/api/v1/auth/session', '/api/v1/geography/import', '/api/v1/geography/provinces/',
    '/api/v1/geography/places/0', '/api/v1/geography/places/01', '/api/v1/geography/places/private-id',
    'https://external.invalid/api/v1/geography/provinces', '//external.invalid/api/v1/geography/provinces',
    '/api/v1/geography/provinces#private', '/api/v1/geography/../../admin']) assert(!geographyReadRoute('GET', path));
  assert(Object.isFrozen(geographyIngressPaths));
});

test('console exceptions require exact Chromium text and an observed owned geography response, never application/private errors', () => {
  const origin = 'https://localhost:43210';
  const path = `${origin}/api/v1/geography/localities?country=IR&province_id=1`;
  const message = (text, url = path, type = 'error') => ({ text: () => text, location: () => ({ url }), type: () => type });
  const expected = 'Failed to load resource: the server responded with a status of 503 (Service Unavailable)';
  const responses = new Map([[path, 503]]);
  assert(expectedGeographyResourceFailure(message(expected), origin, responses));
  assert.equal(responses.size, 0);
  assert(!expectedGeographyResourceFailure(message(expected), origin, responses), 'A consumed response cannot exempt another console message');
  for (const candidate of [message(expected + ' PRIVATE'), message('PRIVATE selected location'), message('i18n invalid_message'),
    message('Hydration mismatch PRIVATE'), message('Content Security Policy violation'), message(expected, path, 'log'),
    message(expected, path.replace('localhost', 'remote.example.test')), message(expected, `${origin}/api/v1/auth/session`),
    message(expected, `${origin}/_next/static/broken.js`)]) {
    assert(!expectedGeographyResourceFailure(candidate, origin, new Map([[candidate.location().url, 503]])));
  }
  assert(!expectedGeographyResourceFailure(message(expected), origin, new Map([[path, 429]])));
  const favicon = `${origin}/favicon.ico`;
  assert(expectedGeographyResourceFailure(message('Failed to load resource: the server responded with a status of 404 (Not Found)', favicon), origin, new Map([[favicon, 404]])));
});

test('geography evidence requires both fresh locales, every journey/check, exact measured service counts and source identity', () => {
  assertGeographyReport(fullReport(), identity);
  for (const mutate of [(value) => value.skipped++, (value) => value.failed++, (value) => value.cleanup.completed = false,
    (value) => value.scope = 'partial', (value) => value.tests++, (value) => value.checks.pop(),
    (value) => value.checks.push(value.checks[0]), (value) => value.localeEvidence.pop(),
    (value) => value.localeEvidence[1].locale = 'en', (value) => value.localeEvidence[1].journeys.pop(),
    (value) => value.localeEvidence[1].checks.pop(), (value) => value.localeEvidence[1].services.violations++,
    (value) => value.localeEvidence[1].services.delayed = 0, (value) => value.localeEvidence[1].services.real++,
    (value) => delete value.localeEvidence[1].services.statuses[409], (value) => delete value.localeEvidence[1].services.statuses[429],
    (value) => value.localeEvidence[1].services.endpoints.lookup = 0,
    (value) => value.localeEvidence[1].services.private = 'PRIVATE', (value) => value.binaryEvidence.api = 'cached',
    (value) => value.cleanup.private = 'PRIVATE',
    (value) => value.identity.source = 'f'.repeat(64), (value) => value.private = 'PRIVATE']) {
    const invalid = structuredClone(fullReport()); mutate(invalid); assert.throws(() => assertGeographyReport(invalid, identity));
  }
});

test('browser report invalidates stale success and only publishes after both verified teardowns', async (t) => {
  const directory = await temporary(t), path = resolve(directory, 'geography-evidence.json');
  await writeFile(path, '{"status":"passed","checks":["stale"]}');
  let closed = 0, opened = 0;
  const report = await runGeographyBrowser({ directory, identify: async () => identity, guard: () => () => {},
    start: async () => {
      await assert.rejects(access(path)); assert.equal(closed, opened); opened++;
      return { identity, binaryEvidence, close: async () => { closed++; return { completed: true }; } };
    }, validate: async (_, locale) => localeEvidence(locale) });
  assertGeographyReport(report, identity); assert.equal(opened, geographyLocales.length); assert.equal(closed, geographyLocales.length);
  assert.deepEqual(JSON.parse(await readFile(path)), report);
});

test('browser report refuses startup, assertion, locale, binary, source, callback and cleanup failures without stale success', async (t) => {
  for (const failure of ['startup', 'assertion', 'locale', 'binary', 'source', 'callback', 'cleanup', 'unconfirmed-cleanup']) await t.test(failure, async (t) => {
    const directory = await temporary(t), path = resolve(directory, 'geography-evidence.json');
    await writeFile(path, '{"status":"passed"}'); let interrupt, opened = 0;
    await assert.rejects(runGeographyBrowser({ directory, identify: async () => identity,
      guard: (callback) => { interrupt = callback; return () => {}; },
      start: async () => {
        opened++; if (failure === 'startup') throw new Error('PRIVATE');
        return { identity: failure === 'source' ? { ...identity, source: 'f'.repeat(64) } : identity,
          binaryEvidence: failure === 'binary' && opened === 2 ? { ...binaryEvidence, api: 'f'.repeat(64) } : binaryEvidence,
          close: async () => { if (failure === 'cleanup') throw new Error('PRIVATE'); return failure === 'unconfirmed-cleanup' ? undefined : { completed: true }; } };
      }, validate: async (_, locale) => { if (failure === 'assertion') throw new Error('PRIVATE');
        if (failure === 'callback') await interrupt();
        return localeEvidence(failure === 'locale' ? 'unknown' : locale); } }));
    await assert.rejects(access(path));
  });
});

test('supervised geography commands certify exit and tree cleanup, bound output and suppress private failures', async (t) => {
  for (const [script, pass] of [["process.stdout.write('fixed')", true], ["process.stderr.write('PRIVATE');process.exit(1)", false],
    ["process.stdout.write('PRIVATE'.repeat(25000))", false]]) await t.test(script.length.toString(), async () => {
    const lifecycle = acceptanceLifecycle(), resources = [], close = portalCleanup(resources);
    try {
      const process = superviseGeographyProcess(globalThis.process.execPath, ['-e', script], { lifecycle, resources, finite: true });
      if (pass) assert.equal(await process.result(), 'fixed');
      else await assert.rejects(process.result(), (error) => !error.message.includes('PRIVATE'));
    } finally { lifecycle.beginTeardown(); await close(); lifecycle.release(); }
  });
});

test('supervised long-lived geography processes stop on owned teardown and interruption, never certify a finite build', async (t) => {
  for (const interrupted of [false, true]) await t.test(String(interrupted), async () => {
    const lifecycle = acceptanceLifecycle(), resources = [], close = portalCleanup(resources);
    try {
      const supervised = superviseGeographyProcess(process.execPath, ['-e', "process.stdout.write('ready');setInterval(()=>{},1000)"], { lifecycle, resources });
      await once(supervised.child.stdout, 'data');
      supervised.assertHealthy();
      await assert.rejects(supervised.result(), /Long-lived service/);
      if (interrupted) process.emit('SIGTERM');
      lifecycle.beginTeardown();
      assert.deepEqual(await close(), { completed: true });
      assert(supervised.child.exitCode !== null || supervised.child.signalCode !== null);
      assert.equal(close(), close());
      if (interrupted) assert.throws(() => lifecycle.signal.throwIfAborted(), /interrupted/);
    } finally { lifecycle.beginTeardown(); await close(); lifecycle.release(); }
  });
});

test('geography layout probes reject horizontal overflow, escaped modal focus and undersized touch targets without DOM text', () => {
  const inspect = ({ width = 44, scrollWidth = 320, focus = true, dialogRight = 320 } = {}) => {
    const element = { checkVisibility: () => true, matches: () => false,
      getBoundingClientRect: () => ({ width, height: 44, left: 0, right: width }) };
    const dialog = { contains: () => focus, getBoundingClientRect: () => ({ left: 0, top: 0, right: dialogRight, bottom: 256 }), querySelectorAll: () => [element] };
    return structuredClone(runInNewContext(`(${geographyBounds})()`, { innerWidth: 320, innerHeight: 256,
      document: { documentElement: { scrollWidth }, querySelector: () => dialog, activeElement: { matches: () => false } } }));
  };
  assert.deepEqual(inspect(), []);
  assert(inspect({ width: 43 }).includes('touch-target-below-44'));
  assert(inspect({ scrollWidth: 321.5 }).includes('horizontal-overflow'));
  assert(inspect({ focus: false }).includes('dialog-focus-escaped'));
  assert(inspect({ dialogRight: 322 }).includes('dialog-outside-viewport'));
});

test('geography target and CI retain exact separate package inventories and required source-bound browser gate', async () => {
  const { parse } = createRequire(import.meta.url)('yaml');
  const workflow = parse(await readFile(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8'));
  assert.deepEqual(workflow.jobs['integration-cell'].strategy.matrix.target, integrationTargets);
  assert.deepEqual(integrationPackages['test-geography-integration'], ['internal/geography']);
  assert.deepEqual(workflow.jobs['race-cell'].strategy.matrix.include.map((entry) => entry.package), racePackages);
  assert(workflow.jobs.publish.needs.includes('geography-browser'));
  const job = workflow.jobs['geography-browser'];
  assert.equal(job['runs-on'], 'ubuntu-24.04');
  const commands = job.steps.map((step) => step.run ?? '').join('\n');
  for (const requirement of ['postgresql-client-16', 'geography-browser.test.mjs', 'playwright install --with-deps chromium',
    'nx run web:test-geography-browser --skipNxCache', 'verify-geography']) assert(commands.includes(requirement));
  assert.doesNotMatch(commands, /DATABASE_URL|data\/cities|data\/types|--integration.*run=/);
  assert(job.steps.some((step) => step.with?.['if-no-files-found'] === 'error'));
  assert(workflow.jobs.publish.steps.some((step) => step.run?.includes('verify-geography')));
  const { nx } = JSON.parse(await readFile(new URL('../../apps/web/package.json', import.meta.url)));
  const target = nx.targets['test-geography-browser'];
  assert.equal(target.cache, false); assert.equal(target.parallelism, false);
  assert.equal(target.command, 'node .github/scripts/geography-browser.mjs');
  assert.deepEqual(target.dependsOn, ['build', { projects: ['identity-api'], target: 'sqlc-generate' }]);
  const harness = await readFile(new URL('./geography-harness.mjs', import.meta.url), 'utf8');
  assert.match(harness, /startPortalServices\(\{ lifecycle \}\)/);
  assert.match(harness, /assertIdentity\(await identify\(\), identity\)/);
  assert.match(harness, /createDisposableGeographyApp/);
  assert.doesNotMatch(harness, /shared|--volumes-from|process\.env\.DATABASE_URL|route\.fulfill|route\.fetch/);
  const browser = await readFile(new URL('./geography-browser.mjs', import.meta.url), 'utf8');
  assert.match(browser, /mask: \[page\.locator\('input,bdi,\[role=status\],\[data-location-selected\],\[data-geography-private\]'/);
  assert.match(harness, /tlsCA: tls\.ca, tlsCAPath/);
  assert.match(browser, /resources\.push\(trustRegistrationFixtureCA\(harness\.tlsCA, harness\.tlsCAPath\)\)/);
  assert.doesNotMatch(browser, /ignoreHTTPSErrors|NODE_TLS_REJECT_UNAUTHORIZED/);
  assert.doesNotMatch(browser, /tracing|recordHar|recordVideo|storageState|snapshot|console\.log\([^\n]*(?:body|response|selection)/);
  assert.equal(geographyNames.en.province, 'Province (required)');
  assert.equal(geographyNames['fa-IR'].locality, 'شهر، منطقه شهری یا روستا (اختیاری)');
});
