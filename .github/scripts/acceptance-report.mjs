import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hashFile, runCommand } from './release-images.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const identityGoModule = 'github.com/hatefsystems/identity/apps/identity-api';

export function assertGoModule(source) {
  const declarations = [...source.matchAll(/^module[\t ]+([^\s]+)[\t ]*(?:\/\/[^\r\n]*)?\r?$/gm)];
  assert(declarations.length === 1 && declarations[0][1] === identityGoModule, 'Acceptance Go module does not match the canonical package profile');
}

export const integrationPackages = Object.freeze({
  'test-security-db': ['internal/dbintegration', 'internal/migrate', 'cmd/migrate', 'cmd/admin-roles', 'cmd/admin-legal', 'internal/recovery', 'internal/webauthn', 'internal/privacy', 'internal/server', 'internal/audit/signer', 'internal/natsjs', 'internal/pglock', 'internal/rbac', 'internal/legalhold', 'internal/adminaction', 'internal/session', 'internal/legalpolicy', 'internal/legalworkflow', 'internal/legalreport', 'internal/smsotp/smsir', 'internal/smtptransport', 'cmd/registration-cleanup'],
  'test-admin-integration': ['internal/adminaction', 'internal/legalhold', 'internal/rbac', 'internal/session', 'internal/server', 'internal/audit/signer', 'internal/pglock'],
  'test-retention-integration': ['internal/audit/retention', 'internal/audit/ledgerproof', 'internal/retentiondbintegration'],
  'test-legal-workflow-integration': ['internal/legalpolicy', 'internal/legalworkflow', 'internal/legalreport', 'internal/server'],
  'test-grpc-integration': ['internal/identitygrpc', 'internal/session', 'internal/oidc/token', 'internal/oidc/dpop'],
  'test-lifecycle-integration': ['internal/lifecycle'],
  'test-portal-integration': ['internal/profile', 'internal/privacy', 'internal/session', 'internal/server', 'internal/webauthn', 'internal/recovery', 'internal/stepup', 'internal/oidc/dpop', 'internal/oidc/token', 'internal/lifecycle', 'internal/identitygrpc', 'internal/oidc/clientauth', 'internal/mfa', 'internal/smsotp', 'internal/registration'],
});
for (const packages of Object.values(integrationPackages)) Object.freeze(packages);
export const integrationTargets = Object.freeze(Object.keys(integrationPackages));
export const racePackages = Object.freeze(['./internal/recovery', './internal/mfa', './internal/oidc/clientauth', './internal/adminaction', './internal/smsotp', './internal/registration', './internal/audit/signer']);
export const raceToolchainProfile = 'linux-amd64-cgo-go1.26.5-gcc';
const digest = /^[0-9a-f]{64}$/;
const imageDigest = /^sha256:[0-9a-f]{64}$/;
const generatedRoots = ['apps/identity-api/internal/db', 'libs/schemas/gen/go', 'libs/schemas/gen/ts'];
export const registrationLocales = Object.freeze(['en', 'fa-IR']);
export const registrationJourneys = Object.freeze(['desktop-light', 'desktop-dark', 'mobile-light', 'mobile-dark']);
export const registrationLocaleChecks = Object.freeze([
  'unicode-canonical-mailbox', 'explicit-smtputf8-email-proof', 'email-resend-proof-invalidation',
  'explicit-smsir-verify-contract', 'leading-zero-otp-preserved', 'corrected-otp-same-reference',
  'missing-capability-denied', 'foreign-jkt-denied', 'wrong-browser-link-denied',
  'ownership-before-account-birth', 'resident-uv-passkey', 'atomic-unprivileged-account-birth',
  'fresh-discoverable-login', 'proof-replay-denied', 'expired-authority-denied', 'cancel-clears-authority',
  'passkey-cancellation-no-birth', 'unsupported-passkey-inert', 'rate-limit-retry-after',
  'lost-completion-durable-receipt', 'completion-pending-deadline-handoff', 'cross-tab-key-change-clears',
  'desktop-mobile-light-dark', 'keyboard-focus-status', 'noscript-inert',
  'technical-email-ltr-roundtrip', 'native-numeric-ascii-wire', 'registration-phase-headings',
  'email-tab-handoff', 'real-theme-preferences', 'registration-display-preferences',
]);
export const registrationChecks = Object.freeze([
  'immutable-quality-image', 'isolated-production-services', 'packaged-migration-cleanup',
  ...registrationLocaleChecks, 'proof-storage-console-network-private', 'verified-owned-teardown',
]);

async function treeFiles(root, base = root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    assert(!entry.isSymbolicLink(), 'Acceptance trees must not contain symbolic links');
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) files.push(...await treeFiles(path, base));
    else if (entry.isFile()) files.push(path.slice(base.length + 1).replaceAll('\\', '/'));
  }
  return files.sort();
}

export async function fingerprintFiles(root, files) {
  const hash = createHash('sha256');
  for (const file of [...files].sort()) {
    let bytes;
    try { bytes = await readFile(resolve(root, file)); }
    catch (error) { if (error.code !== 'ENOENT') throw error; bytes = Buffer.from('[deleted]'); }
    hash.update(JSON.stringify([file, bytes.length]) + '\n').update(bytes);
  }
  return hash.digest('hex');
}

export async function acceptanceIdentity({ root = workspace, env = process.env } = {}) {
  assertGoModule(await readFile(resolve(root, 'apps/identity-api/go.mod'), 'utf8'));
  const git = (args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 16 * 1024 * 1024 });
    assert(!result.error && result.status === 0, 'Acceptance source inventory failed');
    return result.stdout;
  };
  const revision = git(['rev-parse', 'HEAD']).trim();
  assert(/^[0-9a-f]{40}$/.test(revision), 'Acceptance requires a full source revision');
  const files = [...new Set(git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean))]
    .filter((file) => !/^(?:\.kilo\/|\.agents\/|graphify-out\/)/.test(file) &&
      !/(?:^|\/)(?:node_modules|bin|\.next|coverage|test-output)\//.test(file) &&
      !generatedRoots.some((path) => file.startsWith(path + '/')));
  assert(files.length > 0, 'Acceptance source inventory is empty');
  const generated = {};
  for (const path of generatedRoots) {
    const files = await treeFiles(resolve(root, path));
    assert(files.length > 0, 'Acceptance generated inventory is empty');
    generated[path] = { files: files.length, sha256: await fingerprintFiles(resolve(root, path), files) };
  }
  return { revision, source: await fingerprintFiles(root, files), generated,
    runId: env.GITHUB_RUN_ID || env.ACCEPTANCE_RUN_ID || 'local', runAttempt: env.GITHUB_RUN_ATTEMPT || '1' };
}

export function assertIdentity(identity, expected = identity) {
  assert(identity && /^[0-9a-f]{40}$/.test(identity.revision) && digest.test(identity.source), 'Invalid source identity');
  assert.deepEqual(Object.keys(identity.generated).sort(), [...generatedRoots].sort(), 'Wrong generated inventory');
  for (const value of Object.values(identity.generated)) assert(value.files > 0 && digest.test(value.sha256), 'Invalid generated fingerprint');
  assert(typeof identity.runId === 'string' && identity.runId.length > 0 && /^\d+$/.test(identity.runAttempt), 'Invalid acceptance run identity');
  assert.deepEqual(identity, expected, 'Acceptance source/generated/run identity mismatch');
}

export function assertExecutedEvidence(result, expectedPackages) {
  assert(result && result.exit === 0 && result.signal === null, 'Required process did not exit successfully');
  assert(Number.isSafeInteger(result.packages) && result.packages > 0 && Number.isSafeInteger(result.tests) && result.tests > 0 && result.failed === 0 && result.skipped === 0, 'Missing evidence, failure or skip');
  assert(Array.isArray(result.packageEvidence), 'Missing exact package evidence');
  assert.deepEqual(result.packageEvidence.map((item) => item.package).sort(), expectedPackages.map((name) => `${identityGoModule}/${name}`).sort(), 'Wrong or duplicate executed package inventory');
  assert.equal(result.packages, expectedPackages.length);
  let tests = 0;
  for (const item of result.packageEvidence) {
    assert(Array.isArray(item.tests) && item.tests.length > 0 && item.tests.length <= 50_000, 'Package produced no tests');
    assert.equal(new Set(item.tests).size, item.tests.length, 'Duplicate executed tests');
    for (const name of item.tests) assert(/^(?:Test|Example|Fuzz)[A-Za-z0-9_]*(?:\/[a-f0-9]{64})?$/.test(name), 'Invalid executed test identity');
    tests += item.tests.length;
  }
  assert.equal(result.tests, tests, 'Test count does not match exact evidence');
}

export function assertRaceToolchain(toolchain) {
  assert(toolchain && typeof toolchain === 'object' && !Array.isArray(toolchain) &&
    Object.keys(toolchain).sort().join(',') === 'compiler,go,profile,schema' &&
    toolchain.schema === 1 && toolchain.profile === raceToolchainProfile, 'Missing or unsupported race toolchain profile');
  const { go, compiler } = toolchain;
  assert(go && typeof go === 'object' && !Array.isArray(go) &&
    Object.keys(go).sort().join(',') === 'CGO_ENABLED,GOARCH,GOHOSTOS,GOOS,GOVERSION' &&
    go.GOOS === 'linux' && go.GOHOSTOS === 'linux' && go.GOARCH === 'amd64' && go.CGO_ENABLED === '1',
  'Race toolchain requires actual Linux host/target amd64 CGO');
  const version = typeof go.GOVERSION === 'string' && /^go([1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(go.GOVERSION);
  assert(version && (Number(version[1]) > 1 || Number(version[2]) > 26 ||
    (Number(version[2]) === 26 && Number(version[3]) >= 5)), 'Race toolchain requires stable Go 1.26.5 or newer');
  assert(compiler && typeof compiler === 'object' && !Array.isArray(compiler) &&
    Object.keys(compiler).sort().join(',') === 'name,target,version' && compiler.name === 'gcc' &&
    typeof compiler.version === 'string' && /^[1-9]\d{0,2}\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})$/.test(compiler.version) &&
    typeof compiler.target === 'string' && /^x86_64-(?:[a-z0-9][a-z0-9_]{0,31}-)?linux-(?:gnu|musl)$/.test(compiler.target),
  'Race toolchain requires a verified GCC Linux x86_64 target');
}

export function aggregateReports(reports, kind, identity) {
  assert(['integration', 'race'].includes(kind), 'Unknown acceptance aggregate');
  assertIdentity(identity);
  assert.notEqual(identity.runId, 'local', 'Local aggregation requires an explicit ACCEPTANCE_RUN_ID shared by all seven cells');
  const expected = kind === 'integration' ? integrationTargets.map((name) => `identity-api:${name}`) : racePackages.map((name) => `identity-api:${name}`);
  assert.equal(reports.length, 7, 'Acceptance aggregate requires exactly seven reports');
  assert.deepEqual(reports.map((report) => report.results?.[0]?.target).sort(), [...expected].sort(), 'Missing, duplicate or unknown acceptance cell');
  for (const report of reports) {
    assert(report.schema === 1 && report.kind === kind && report.scope === 'partial' && report.status === 'passed' && report.cleanup?.completed === true && report.results.length === 1, 'Invalid/failed partial cell');
    assertIdentity(report.identity, identity);
    if (kind === 'race') {
      assertRaceToolchain(report.toolchain);
      assert.deepEqual(report.toolchain, reports[0].toolchain, 'Race cells used different toolchains');
    }
    const result = report.results[0];
    const name = result.target.slice('identity-api:'.length);
    assertExecutedEvidence(result, kind === 'integration' ? integrationPackages[name] : [name.slice(2)]);
    for (const value of [report.timings?.startup, report.timings?.cleanup, result.duration]) assert(Number.isSafeInteger(value) && value >= 0, 'Missing lifecycle timings');
  }
  return { schema: 1, kind, scope: 'full', status: 'passed', identity, cleanup: { completed: true },
    ...(kind === 'race' ? { toolchain: reports[0].toolchain } : {}), results: reports.flatMap((report) => report.results) };
}

export function assertRegistrationReport(report, manifest) {
  assert(report?.schema === 2 && report.kind === 'registration-browser' && report.status === 'passed' && report.scope === 'full' && report.cleanup?.completed === true, 'Registration acceptance did not pass with verified cleanup');
  assert.deepEqual(Object.keys(report).sort(), ['apiImageId', 'checks', 'cleanup', 'exit', 'failed', 'identity', 'kind', 'localeEvidence', 'providers', 'schema', 'scope', 'skipped', 'status', 'tests'], 'Unexpected private registration report fields');
  assertIdentity(report.identity, manifest.identity);
  assert(imageDigest.test(manifest.imageId) && report.apiImageId === manifest.imageId, 'Registration API image mismatch');
  assert(report.exit === 0 && report.failed === 0 && report.skipped === 0 && Number.isSafeInteger(report.tests) && report.tests > 0 && Array.isArray(report.checks) && report.checks.length > 0, 'Registration acceptance lacks executed evidence');
  assert.equal(new Set(report.checks).size, report.checks.length, 'Duplicate registration evidence');
  for (const check of report.checks) assert(/^[a-z][a-z0-9-]{0,127}$/.test(check), 'Registration evidence must use fixed private-data-free check identifiers');
  assert.deepEqual([...report.checks].sort(), [...registrationChecks].sort(), 'Incomplete registration check inventory');
  assert.equal(report.tests, report.checks.length, 'Registration check count mismatch');
  assert(Array.isArray(report.localeEvidence) && report.localeEvidence.length === registrationLocales.length, 'Missing isolated registration locale evidence');
  assert.deepEqual(report.localeEvidence.map((entry) => entry.locale).sort(), [...registrationLocales].sort(), 'Missing or duplicate registration locale');
  const providers = { mail: 0, sms: 0, auth: 0, violations: 0 };
  for (const entry of report.localeEvidence) {
    assert.deepEqual(Object.keys(entry).sort(), ['checks', 'journeys', 'locale', 'providers', 'sessions'], 'Unexpected private registration locale evidence');
    assert(Array.isArray(entry.checks) && Array.isArray(entry.journeys), 'Missing executed registration locale inventory');
    assert.deepEqual([...entry.checks].sort(), [...registrationLocaleChecks].sort(), 'Incomplete registration locale checks');
    assert.deepEqual([...entry.journeys].sort(), [...registrationJourneys].sort(), 'Missing or duplicate registration locale journey');
    assert.equal(entry.sessions, registrationJourneys.length, 'Registration locale did not establish one fresh session per journey');
    assert(entry.providers && typeof entry.providers === 'object' && !Array.isArray(entry.providers), 'Missing measured registration provider counts');
    assert.deepEqual(Object.keys(entry.providers).sort(), ['auth', 'mail', 'sms', 'violations'], 'Unexpected private provider evidence');
    for (const key of Object.keys(providers)) {
      assert(Number.isSafeInteger(entry.providers[key]) && entry.providers[key] >= 0 && entry.providers[key] <= 1000, 'Invalid measured registration provider count');
      providers[key] += entry.providers[key];
    }
    assert(entry.providers.mail === 8 && entry.providers.sms === 5 && entry.providers.violations === 0, 'Registration locale provider contract did not pass');
  }
  assert.deepEqual(report.providers, providers, 'Aggregate registration provider counts do not match measured locale deltas');
  assert(providers.auth > 0, 'Registration SMTP authentication evidence missing');
}

export async function exportAcceptanceImage(reference, directory, { identify = acceptanceIdentity, run = runCommand } = {}) {
  assert(/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,254}$/.test(reference), 'Invalid acceptance image reference');
  const identity = await identify();
  assertIdentity(identity);
  const [image] = JSON.parse(await run('docker', ['image', 'inspect', reference]));
  assert(imageDigest.test(image.Id) && image.Os === 'linux' && image.Architecture === 'amd64', 'Wrong acceptance API platform/ID');
  assert.equal(image.Config.Labels['org.opencontainers.image.revision'], identity.revision, 'Acceptance image source mismatch');
  await mkdir(directory, { recursive: true });
  const archive = resolve(directory, 'acceptance-api.tar');
  await run('docker', ['image', 'save', '--output', archive, image.Id], { timeout: 600_000 });
  const stat = await lstat(archive);
  assert(stat.isFile() && stat.size > 0 && stat.size <= 20 * 1024 ** 3, 'Invalid exported acceptance API archive');
  const manifest = { schema: 1, kind: 'api', imageId: image.Id, identity, sha256: await hashFile(archive) };
  await writeFile(resolve(directory, 'acceptance-api.json'), JSON.stringify(manifest) + '\n');
  return manifest;
}

export async function loadAcceptanceImage(directory, { identify = acceptanceIdentity, run = runCommand } = {}) {
  const manifest = await readReport(resolve(directory, 'acceptance-api.json'));
  assert(manifest.schema === 1 && manifest.kind === 'api' && imageDigest.test(manifest.imageId) && digest.test(manifest.sha256), 'Invalid acceptance API manifest');
  assertIdentity(manifest.identity, await identify());
  const archive = resolve(directory, 'acceptance-api.tar');
  const stat = await lstat(archive);
  assert(stat.isFile() && stat.size > 0 && stat.size <= 20 * 1024 ** 3, 'Invalid acceptance API archive');
  assert.equal(await hashFile(archive), manifest.sha256, 'Acceptance API checksum mismatch');
  await run('docker', ['image', 'load', '--input', archive], { timeout: 600_000 });
  const [image] = JSON.parse(await run('docker', ['image', 'inspect', manifest.imageId]));
  assert.equal(image.Id, manifest.imageId);
  assert.equal(image.Config.Labels['org.opencontainers.image.revision'], manifest.identity.revision);
  assert(image.Os === 'linux' && image.Architecture === 'amd64', 'Loaded acceptance image platform mismatch');
  return manifest;
}

export async function readReport(path) {
  const stat = await lstat(path);
  assert(stat.isFile() && stat.size > 0 && stat.size <= 16 * 1024 * 1024, 'Invalid bounded acceptance report');
  return JSON.parse(await readFile(path, 'utf8'));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [command, ...args] = process.argv.slice(2);
    if (command === 'export-api' && args.length === 2) await exportAcceptanceImage(args[0], args[1]);
    else if (command === 'load-api' && args.length === 1) console.log((await loadAcceptanceImage(args[0])).imageId);
    else if (command === 'aggregate' && args.length === 3) {
      const [kind, directory, output] = args;
      const files = (await readdir(directory)).filter((name) => name.endsWith('.json'));
      const report = aggregateReports(await Promise.all(files.map((name) => readReport(resolve(directory, name)))), kind, await acceptanceIdentity());
      await writeFile(output, JSON.stringify(report) + '\n');
    } else if (command === 'verify-registration' && args.length === 2) assertRegistrationReport(await readReport(args[0]), await readReport(args[1]));
    else if (command === 'verify-publication' && args.length === 4) {
      const [registration, manifestPath, releasePath, aggregates] = args;
      const manifest = await readReport(manifestPath);
      assertRegistrationReport(await readReport(registration), manifest);
      const release = await readReport(releasePath);
      assert.equal(release.imageId, manifest.imageId, 'Publication API differs from accepted API');
      assert.equal(release.revision, manifest.identity.revision, 'Publication source differs from accepted source');
      assert.equal(release.runId, manifest.identity.runId, 'Publication workflow differs from accepted workflow');
      assert.equal(manifest.identity.runId, process.env.GITHUB_RUN_ID, 'Stale publication acceptance run');
      assert.equal(manifest.identity.runAttempt, process.env.GITHUB_RUN_ATTEMPT || '1', 'Stale publication acceptance attempt');
      for (const kind of ['integration', 'race']) {
        const report = await readReport(resolve(aggregates, `${kind}-aggregate.json`));
        assert(report.schema === 1 && report.scope === 'full' && report.status === 'passed' && report.kind === kind && report.cleanup.completed === true && report.results.length === 7, 'Missing publication aggregate');
        assertIdentity(report.identity, manifest.identity);
        aggregateReports(report.results.map((result) => ({ schema: 1, kind, scope: 'partial', status: 'passed', identity: report.identity, cleanup: report.cleanup,
          ...(kind === 'race' ? { toolchain: report.toolchain } : {}), results: [result], timings: { startup: 0, cleanup: 0 } })), kind, manifest.identity);
      }
    } else throw new Error('Invalid acceptance report command');
  } catch { console.error('Acceptance report/artifact validation failed; private diagnostics suppressed.'); process.exitCode = 1; }
}
