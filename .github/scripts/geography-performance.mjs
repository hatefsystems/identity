import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { acceptanceIdentity, assertIdentity } from './acceptance-report.mjs';
import { acceptanceLifecycle, startPortalServices } from './portal-harness.mjs';
import { geographyEnvironment, geographyOperatorEnvironment, geographyRoleSQL } from './geography-harness.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const backend = resolve(workspace, 'apps/identity-api');
const categories = ['browse', 'rare-prefix', 'common-prefix', 'empty-result', 'later-page'];

export function performanceInvocation(args) {
  assert(args.length === 3, 'Performance requires three explicit source/manifest paths');
  const result = {};
  for (const argument of args) {
    const match = /^--(cities|types|manifest)=(.+)$/.exec(argument);
    assert(match && !Object.hasOwn(result, match[1]) && isAbsolute(match[2]) && !match[2].includes('\0'),
      'Invalid explicit performance source path');
    result[match[1]] = match[2];
  }
  assert(Object.keys(result).sort().join(',') === 'cities,manifest,types', 'Missing performance source path');
  return result;
}

const planNumbers = ['Actual Startup Time', 'Actual Total Time', 'Actual Rows', 'Actual Loops',
  'Plan Rows', 'Plan Width', 'Shared Hit Blocks', 'Shared Read Blocks', 'Shared Dirtied Blocks',
  'Shared Written Blocks', 'Temp Read Blocks', 'Temp Written Blocks'];
const nodeTypes = new Set(['Limit', 'Index Scan', 'Index Only Scan', 'Bitmap Heap Scan', 'Bitmap Index Scan',
  'BitmapAnd', 'BitmapOr', 'Seq Scan', 'Sort', 'Incremental Sort', 'Result', 'Gather', 'Gather Merge']);

// EXPLAIN predicates can embed original geographic labels. Retain structure and
// measurements only, never Filter, Index Cond, Output, query text or rejected data.
export function sanitizePlan(node, depth = 0) {
  assert(node && typeof node === 'object' && depth < 32 && nodeTypes.has(node['Node Type']), 'Unknown performance plan structure');
  const result = { node: node['Node Type'] };
  for (const key of planNumbers) if (Object.hasOwn(node, key)) {
    assert(Number.isFinite(node[key]) && node[key] >= 0, 'Invalid performance plan measurement');
    result[key] = node[key];
  }
  if (node['Index Name']) {
    assert(['idx_geography_localities', 'idx_geography_provinces', 'geography_place_versions_pkey'].includes(node['Index Name']),
      'Unexpected geography index');
    result.index = node['Index Name'];
  }
  if (node.Plans) {
    assert(Array.isArray(node.Plans) && node.Plans.length <= 16, 'Unbounded performance plan');
    result.plans = node.Plans.map((child) => sanitizePlan(child, depth + 1));
  }
  return result;
}

export function percentile95(values) {
  assert(values.length === 100 && values.every((value) => Number.isFinite(value) && value >= 0),
    'Performance evidence requires 100 measured queries');
  return [...values].sort((left, right) => left - right)[94];
}

function command(binary, args, env, input, lifecycle, timeout = 60_000) {
  lifecycle.check();
  const result = spawnSync(binary, args, { cwd: backend, env: geographyEnvironment(env), input, encoding: 'utf8',
    timeout: Math.max(1, Math.min(timeout, lifecycle.remaining())), maxBuffer: 2 * 1024 * 1024, windowsHide: true });
  assert(!result.error && result.status === 0 && result.signal === null, 'Owned geography performance operation failed; diagnostics suppressed');
  return result.stdout.trim();
}

function databaseEnvironment(url) {
  const value = new URL(url);
  assert(value.protocol === 'postgres:' && value.hostname === '127.0.0.1' && value.port &&
    /^\/portal_browser_[a-f0-9]{32}$/.test(value.pathname), 'Performance requires a run-owned database');
  return { PGHOST: value.hostname, PGPORT: value.port, PGUSER: decodeURIComponent(value.username),
    PGPASSWORD: decodeURIComponent(value.password), PGDATABASE: value.pathname.slice(1), PGSSLMODE: 'disable',
    PGCONNECT_TIMEOUT: '5', PGOPTIONS: '-c statement_timeout=1000 -c lock_timeout=1000' };
}

const literal = (value) => "'" + String(value).replaceAll("'", "''") + "'";
const prefix = (value) => String(value).replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_') + '%';

function scanQuery(sample, category) {
  let query = category === 'rare-prefix' ? sample.rare : category === 'common-prefix' ? sample.common :
    category === 'empty-result' ? '__geography_no_matching_prefix_09__' : '';
  const queryRunes = Array.from(query).slice(0, 80);
  while (Buffer.byteLength(queryRunes.join('')) > 256) queryRunes.pop();
  query = queryRunes.join('');
  // Match the service's explicit C-collated prefix range, including surrogate
  // avoidance and the unbounded upper edge for maximum Unicode scalars.
  let upper = '';
  const runes = [...queryRunes];
  while (runes.length) {
    let scalar = runes.pop().codePointAt(0);
    if (scalar === 0x10ffff) continue;
    scalar++;
    if (scalar >= 0xd800 && scalar <= 0xdfff) scalar = 0xe000;
    upper = runes.join('') + String.fromCodePoint(scalar);
    break;
  }
  const range = query ? `AND search_label>=${literal(query)}::text COLLATE "C"` +
    (upper ? ` AND search_label<${literal(upper)}::text COLLATE "C"` : '') : '';
  const afterName = category === 'later-page' ? sample.after_name : '';
  const afterID = category === 'later-page' ? sample.after_id : '0';
  assert(/^[1-9][0-9]{0,18}$/.test(sample.province) && /^(0|[1-9][0-9]{0,18})$/.test(afterID), 'Invalid owned query coordinate');
  return `SELECT id,search_label FROM public.geography_place_versions
    WHERE revision=1 AND type_id IN (5,7) AND province_id=${sample.province} ${range}
    AND search_label LIKE ${literal(prefix(query))} ESCAPE '\\'
    AND (search_label,id)>(${literal(afterName)}::text COLLATE "C",${afterID}::bigint)
    ORDER BY search_label COLLATE "C",id LIMIT 21`;
}

export async function runGeographyPerformance(input, { directory = process.env.GEOGRAPHY_PERFORMANCE_ARTIFACT_DIR } = {}) {
  const lifecycle = acceptanceLifecycle();
  const report = { schema: 1, kind: 'geography-performance', status: 'failed', cleanup: { completed: false },
    metric: 'PostgreSQL EXPLAIN execution time for bounded locality scan, not end-to-end API latency',
    queries: 0, plans: [] };
  let services, failure;
  try {
    report.identity = await acceptanceIdentity();
    const manifestStat = await lstat(input.manifest);
    assert(manifestStat.isFile() && manifestStat.size > 0 && manifestStat.size <= 16 * 1024,
      'Performance requires a bounded operator manifest');
    const manifestBytes = await readFile(input.manifest);
    assert(manifestBytes.length <= 16 * 1024, 'Performance manifest changed beyond bounds');
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    assert(manifest.complete_snapshot === true && manifest.expected_current_revision === null,
      'Performance requires an operator-asserted complete initial snapshot manifest');
    services = await startPortalServices({ lifecycle });
    const owner = databaseEnvironment(services.environment.DATABASE_URL);
    const sql = (text, env = owner) => command('psql', ['-X', '--no-psqlrc', '-qAt', '-v', 'ON_ERROR_STOP=1'], env, text, lifecycle);
    // The migration identity belongs solely to this newly created service stack.
    command(resolve(backend, 'bin/migrate'), ['up'], geographyOperatorEnvironment('migrate', services.environment.DATABASE_URL), undefined, lifecycle, 120_000);
    const reader = 'geography_reader';
    const importer = 'geography_importer';
    const readerPassword = randomBytes(24).toString('hex');
    const importerPassword = randomBytes(24).toString('hex');
    sql(geographyRoleSQL(owner.PGDATABASE, readerPassword, importerPassword));
    const connection = (role) => {
      const url = new URL(services.environment.DATABASE_URL); url.username = role;
      url.password = role === reader ? readerPassword : importerPassword; return url.href;
    };
    const args = [`--cities=${input.cities}`, `--types=${input.types}`, `--manifest=${input.manifest}`];
    const binary = resolve(backend, 'bin/geography');
    const checked = JSON.parse(command(binary, ['check', ...args], geographyOperatorEnvironment('check', connection(reader)), undefined, lifecycle, 120_000));
    assert(/^[a-f0-9]{64}$/.test(checked.plan_digest) && checked.retirements === 0, 'Unexpected initial performance plan');
    const started = performance.now();
    const applied = JSON.parse(command(binary, ['import', ...args, `--apply-plan=${checked.plan_digest}`],
      geographyOperatorEnvironment('import', connection(importer)), undefined, lifecycle, 600_000));
    report.importMs = Math.round(performance.now() - started);
    assert(applied.catalog_revision === '1', 'Unexpected performance catalog revision');
    sql('ANALYZE public.geography_place_versions; ANALYZE public.geography_types;');
    report.input = { cities_sha256: manifest.cities_sha256, types_sha256: manifest.types_sha256,
      place_count: manifest.place_count, type_count: manifest.type_count, province_count: manifest.province_count };
    report.indexBytes = JSON.parse(sql(`SELECT coalesce(json_agg(json_build_object('index',indexrelname,'bytes',pg_relation_size(indexrelid))), '[]'::json)
      FROM pg_stat_user_indexes WHERE relname='geography_place_versions'`));
    assert(report.indexBytes.length === 3 && report.indexBytes.every((item) =>
      ['idx_geography_localities', 'idx_geography_provinces', 'geography_place_versions_pkey'].includes(item.index) &&
      Number.isSafeInteger(item.bytes) && item.bytes > 0), 'Incomplete performance index evidence');
    // Query labels stay in process memory and private psql stdin. No sample, SQL
    // predicate, result row or full EXPLAIN object is an artifact input.
    const samples = JSON.parse(sql(`WITH provinces AS (
      SELECT province_id,count(*) AS places FROM public.geography_place_versions WHERE revision=1 AND type_id IN(5,7)
      GROUP BY province_id ORDER BY places DESC,province_id LIMIT 20)
      SELECT json_agg(json_build_object('province',p.province_id::text,
      'rare',(SELECT search_label FROM public.geography_place_versions WHERE revision=1 AND type_id IN(5,7) AND province_id=p.province_id ORDER BY search_label COLLATE "C",id DESC LIMIT 1),
      'common',(SELECT left(search_label,1) FROM public.geography_place_versions WHERE revision=1 AND type_id IN(5,7) AND province_id=p.province_id GROUP BY left(search_label,1) ORDER BY count(*) DESC,left(search_label,1) COLLATE "C" LIMIT 1),
      'after_name',coalesce((SELECT search_label FROM public.geography_place_versions WHERE revision=1 AND type_id IN(5,7) AND province_id=p.province_id ORDER BY search_label COLLATE "C",id OFFSET 20 LIMIT 1),''),
      'after_id',coalesce((SELECT id::text FROM public.geography_place_versions WHERE revision=1 AND type_id IN(5,7) AND province_id=p.province_id ORDER BY search_label COLLATE "C",id OFFSET 20 LIMIT 1),'0'))) FROM provinces p`));
    assert(Array.isArray(samples) && samples.length > 0 && samples.length <= 20, 'No representative performance samples');
    const readEnv = databaseEnvironment(connection(reader));
    const [provincePlan] = JSON.parse(sql(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
      SELECT id,search_label FROM public.geography_place_versions WHERE revision=1 AND type_id=2
      ORDER BY search_label COLLATE "C",id LIMIT 21`, readEnv));
    report.provinceBrowse = { executionMs: provincePlan['Execution Time'], plan: sanitizePlan(provincePlan.Plan) };
    for (const sample of samples) for (const category of categories) sql(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${scanQuery(sample, category)}`, readEnv);
    const timings = [];
    for (let index = 0; index < 100; index++) {
      const category = categories[index % categories.length];
      const sample = samples[Math.floor(index / categories.length) % samples.length];
      const [plan] = JSON.parse(sql(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${scanQuery(sample, category)}`, readEnv));
      assert(Number.isFinite(plan['Execution Time']) && plan['Execution Time'] >= 0, 'Missing measured query timing');
      if (category === 'empty-result') assert(plan.Plan['Actual Rows'] === 0, 'Empty-result performance probe unexpectedly matched');
      if (category === 'later-page') assert(sample.after_id !== '0', 'Later-page performance sample lacks a continuation');
      timings.push(plan['Execution Time']);
      if (index < categories.length) report.plans.push({ category, executionMs: plan['Execution Time'], plan: sanitizePlan(plan.Plan) });
    }
    report.queries = timings.length;
    report.p95Ms = percentile95(timings);
    report.maxMs = Math.max(...timings);
    assert(report.p95Ms < 200, 'Warmed locality query p95 exceeded 200ms; retain failure and diagnose plans');
  } catch (error) { failure = error; }
  finally {
    lifecycle.beginTeardown();
    try {
      if (services) report.cleanup = await services.close();
      assert(report.cleanup.completed, 'Geography performance cleanup not confirmed');
      assertIdentity(await acceptanceIdentity(), report.identity);
    } catch (error) { failure ||= error; }
    lifecycle.release();
    report.status = failure ? 'failed' : 'passed';
    if (directory) { await mkdir(directory, { recursive: true }); await writeFile(resolve(directory, 'geography-performance.json'), JSON.stringify(report) + '\n'); }
  }
  console.log(JSON.stringify({ check: 'geography-performance', status: report.status, queries: report.queries,
    ...(report.p95Ms !== undefined ? { p95Ms: report.p95Ms, maxMs: report.maxMs, importMs: report.importMs } : {}), cleanup: report.cleanup.completed }));
  if (failure) throw new Error('Owned geography performance failed; source/private diagnostics suppressed', { cause: failure });
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { await runGeographyPerformance(performanceInvocation(process.argv.slice(2))); }
  catch { console.error('Owned geography performance failed; diagnostics suppressed'); process.exitCode = 1; }
}
