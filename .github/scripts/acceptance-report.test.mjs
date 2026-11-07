import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { aggregateReports, assertExecutedEvidence, assertGoModule, assertIdentity, assertRaceToolchain, assertRegistrationReport, exportAcceptanceImage, fingerprintFiles, identityGoModule, integrationPackages, integrationTargets, loadAcceptanceImage, racePackages, raceToolchainProfile, readReport } from './acceptance-report.mjs';

const identity = { revision: 'a'.repeat(40), source: 'b'.repeat(64), generated: Object.fromEntries(['apps/identity-api/internal/db', 'libs/schemas/gen/go', 'libs/schemas/gen/ts'].map((path) => [path, { files: 1, sha256: 'c'.repeat(64) }])), runId: '123', runAttempt: '1' };
const toolchain = { schema: 1, profile: raceToolchainProfile,
  go: { GOOS: 'linux', GOHOSTOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '1', GOVERSION: 'go1.26.5' },
  compiler: { name: 'gcc', version: '12.2.0', target: 'x86_64-linux-gnu' } };
function reports(kind) {
  return (kind === 'integration' ? integrationTargets : racePackages).map((name) => {
    const packages = kind === 'integration' ? integrationPackages[name] : [name.slice(2)];
    return { schema: 1, kind, scope: 'partial', status: 'passed', identity: structuredClone(identity), cleanup: { completed: true }, timings: { startup: 1, cleanup: 1 },
      ...(kind === 'race' ? { toolchain: structuredClone(toolchain) } : {}),
      results: [{ target: `identity-api:${name}`, exit: 0, signal: null, packages: packages.length, tests: packages.length, failed: 0, skipped: 0, duration: 1,
        packageEvidence: packages.map((name) => ({ package: `${identityGoModule}/${name}`, tests: ['TestExecuted'] })) }] };
  });
}

test('canonical Go package profile is bound to the current source module declaration', async () => {
  assert.equal(identityGoModule, 'github.com/hatefsystems/identity/apps/identity-api');
  assertGoModule(await readFile(new URL('../../apps/identity-api/go.mod', import.meta.url), 'utf8'));
  for (const source of ['module identity-api\n', 'module github.com/foreign/identity/apps/identity-api\n', '',
    `module ${identityGoModule}\nmodule identity-api\n`]) assert.throws(() => assertGoModule(source), /canonical package profile/);
});

for (const kind of ['integration', 'race']) {
  test(`${kind} exact-seven aggregate is full and never substitutes another acceptance lane`, () => {
    const report = aggregateReports(reports(kind), kind, identity);
    assert.equal(report.scope, 'full');
    assert.equal(report.status, 'passed');
    assert.equal(report.results.length, 7);
    assert.equal(report.cleanup.completed, true);
    if (kind === 'race') assert.deepEqual(report.toolchain, toolchain);
    else assert.equal(report.toolchain, undefined);
    assert.throws(() => aggregateReports(reports(kind === 'race' ? 'integration' : 'race'), kind, identity));
  });
  for (const problem of ['missing', 'extra', 'duplicate', 'unknown', 'full-cell', 'failed-cell', 'cleanup', 'revision', 'source', 'generated', 'run', 'attempt', 'skip', 'failure', 'empty-package', 'wrong-package', 'former-module', 'wrong-module', 'empty-tests', 'duplicate-tests', 'counts', 'exit', 'signal', 'timings']) {
    test(`${kind} aggregate rejects ${problem} even when other cells passed`, () => {
      const cells = reports(kind), first = cells[0], result = first.results[0];
      if (problem === 'missing') cells.pop();
      if (problem === 'extra') cells.push(structuredClone(first));
      if (problem === 'duplicate') cells[1] = structuredClone(first);
      if (problem === 'unknown') result.target = 'identity-api:unapproved';
      if (problem === 'full-cell') first.scope = 'full';
      if (problem === 'failed-cell') first.status = 'failed';
      if (problem === 'cleanup') first.cleanup.completed = false;
      if (problem === 'revision') first.identity.revision = 'd'.repeat(40);
      if (problem === 'source') first.identity.source = 'd'.repeat(64);
      if (problem === 'generated') first.identity.generated['apps/identity-api/internal/db'].sha256 = 'd'.repeat(64);
      if (problem === 'run') first.identity.runId = '122';
      if (problem === 'attempt') first.identity.runAttempt = '2';
      if (problem === 'skip') result.skipped = 1;
      if (problem === 'failure') result.failed = 1;
      if (problem === 'empty-package') { result.packageEvidence = []; result.packages = 0; }
      if (problem === 'wrong-package') result.packageEvidence[0].package = `${identityGoModule}/foreign`;
      if (problem === 'former-module') result.packageEvidence[0].package = result.packageEvidence[0].package.replace(identityGoModule, 'identity-api');
      if (problem === 'wrong-module') result.packageEvidence[0].package = result.packageEvidence[0].package.replace(identityGoModule, 'github.com/foreign/identity/apps/identity-api');
      if (problem === 'empty-tests') result.packageEvidence[0].tests = [];
      if (problem === 'duplicate-tests') result.packageEvidence[0].tests.push('TestExecuted');
      if (problem === 'counts') result.tests++;
      if (problem === 'exit') result.exit = 1;
      if (problem === 'signal') result.signal = 'SIGTERM';
      if (problem === 'timings') delete first.timings;
      assert.throws(() => aggregateReports(cells, kind, identity));
    });
  }
}

test('race toolchain profile admits only stable supported Go and actual GCC Linux x86_64', () => {
  assertRaceToolchain(toolchain);
  for (const version of ['go1.26.6', 'go1.27.0']) assertRaceToolchain({ ...toolchain, go: { ...toolchain.go, GOVERSION: version } });
  for (const target of ['x86_64-pc-linux-gnu', 'x86_64-unknown-linux-musl']) assertRaceToolchain({ ...toolchain, compiler: { ...toolchain.compiler, target } });
  for (const invalid of [true, {}, { ...toolchain, profile: 'verified' }, { ...toolchain, verified: true },
    { ...toolchain, go: { ...toolchain.go, GOOS: 'windows' } }, { ...toolchain, go: { ...toolchain.go, GOHOSTOS: 'windows' } },
    { ...toolchain, go: { ...toolchain.go, GOARCH: 'arm64' } }, { ...toolchain, go: { ...toolchain.go, CGO_ENABLED: '0' } },
    { ...toolchain, go: { ...toolchain.go, CGO_ENABLED: true } }, { ...toolchain, go: { ...toolchain.go, path: 'PRIVATE' } },
    { ...toolchain, compiler: { ...toolchain.compiler, target: 'x86_64-w64-mingw32' } },
    { ...toolchain, compiler: { ...toolchain.compiler, target: 'aarch64-linux-gnu' } },
    { ...toolchain, compiler: { ...toolchain.compiler, target: 'x86_64-linux-gnux32' } },
    { ...toolchain, compiler: { ...toolchain.compiler, name: 'clang' } },
    { ...toolchain, compiler: { ...toolchain.compiler, version: 'PRIVATE' } },
    { ...toolchain, compiler: { ...toolchain.compiler, raw: 'PRIVATE' } },
  ]) assert.throws(() => assertRaceToolchain(invalid));
  for (const version of ['go1.25.9', 'go1.26.0', 'go1.26.4', 'go1.26.5rc1', 'devel go1.27', 'go1.27', 'go1.026.5', 'go1.26.005'])
    assert.throws(() => assertRaceToolchain({ ...toolchain, go: { ...toolchain.go, GOVERSION: version } }));
});

test('exact-seven race aggregate requires matching toolchain proofs, never a caller boolean', () => {
  for (const change of [(cell) => delete cell.toolchain, (cell) => cell.toolchain = true,
    (cell) => cell.toolchain = { verified: true }, (cell) => cell.toolchain.go.GOHOSTOS = 'windows',
    (cell) => cell.toolchain.go.CGO_ENABLED = '0', (cell) => cell.toolchain.compiler.target = 'x86_64-w64-mingw32',
    (cell) => cell.toolchain.go.GOVERSION = 'go1.26.4', (cell) => cell.toolchain.go.GOVERSION = 'go1.26.6',
    (cell) => cell.toolchain.compiler.version = '13.3.0',
  ]) {
    const cells = reports('race'); change(cells[3]);
    assert.throws(() => aggregateReports(cells, 'race', identity));
  }
  const cells = reports('race');
  cells[0].results[0].skipped = 1;
  assert.throws(() => aggregateReports(cells, 'race', identity));
  cells[0].results[0].skipped = 0;
  cells[0].results[0].tests = 0;
  assert.throws(() => aggregateReports(cells, 'race', identity));
});

test('source fingerprint binds filenames, bytes and deletions rather than just git HEAD', async () => {
  await mkdir(resolve(tmpdir(), 'kilo'), { recursive: true });
  const directory = await mkdtemp(resolve(tmpdir(), 'kilo', 'acceptance-fingerprint-'));
  try {
    await writeFile(resolve(directory, 'a'), 'one');
    await writeFile(resolve(directory, 'b'), 'two');
    const original = await fingerprintFiles(directory, ['a', 'b']);
    assert.equal(await fingerprintFiles(directory, ['b', 'a']), original);
    await writeFile(resolve(directory, 'a'), 'changed');
    assert.notEqual(await fingerprintFiles(directory, ['a', 'b']), original);
    await rm(resolve(directory, 'a'));
    assert.notEqual(await fingerprintFiles(directory, ['a', 'b']), original);
    assert.notEqual(await fingerprintFiles(directory, ['b']), original);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('identity refuses missing and empty generated trees and stale attempts', () => {
  assertIdentity(identity);
  for (const change of [(value) => delete value.generated['libs/schemas/gen/ts'], (value) => value.generated['apps/identity-api/internal/db'].files = 0, (value) => value.source = 'not-a-hash', (value) => value.runAttempt = 'unknown']) {
    const value = structuredClone(identity); change(value); assert.throws(() => assertIdentity(value));
  }
});

test('local partial cells cannot certify an aggregate without a shared explicit run identity', () => {
  const cells = reports('integration');
  const local = { ...identity, runId: 'local' };
  for (const cell of cells) cell.identity = local;
  assert.throws(() => aggregateReports(cells, 'integration', local), /ACCEPTANCE_RUN_ID/);
});

test('passing process and one skip or absent package evidence cannot certify a race', () => {
  const result = reports('race')[0].results[0];
  assertExecutedEvidence(result, ['internal/recovery']);
  assert.throws(() => assertExecutedEvidence({ ...result, skipped: 1 }, ['internal/recovery']));
  assert.throws(() => assertExecutedEvidence({ ...result, packageEvidence: [] }, ['internal/recovery']));
});

test('registration report binds the exact publication image and source generation', () => {
  const imageId = `sha256:${'d'.repeat(64)}`;
  const manifest = { imageId, identity };
  const report = { schema: 1, kind: 'registration-browser', scope: 'full', status: 'passed', identity, apiImageId: imageId, cleanup: { completed: true }, exit: 0, failed: 0, skipped: 0, tests: 1, checks: ['production-registration'] };
  assertRegistrationReport(report, manifest);
  for (const change of [{ apiImageId: `sha256:${'e'.repeat(64)}` }, { scope: 'partial' }, { status: 'failed' }, { cleanup: { completed: false } }, { skipped: 1 }, { failed: 1 }, { tests: 0 }, { checks: [] }, { identity: { ...identity, source: 'f'.repeat(64) } }]) assert.throws(() => assertRegistrationReport({ ...report, ...change }, manifest));
});

test('acceptance API export/load binds exact checksum, source and generation on nonrelease runs too', async () => {
  await mkdir(resolve(tmpdir(), 'kilo'), { recursive: true });
  const directory = await mkdtemp(resolve(tmpdir(), 'kilo', 'acceptance-api-test-'));
  const imageId = `sha256:${'d'.repeat(64)}`;
  const calls = [];
  const run = async (command, args) => {
    assert.equal(command, 'docker'); calls.push(args);
    if (args[1] === 'save') { await writeFile(args[3], 'owned-image-archive'); return ''; }
    if (args[1] === 'load') return '';
    assert.equal(args[1], 'inspect');
    return JSON.stringify([{ Id: imageId, Os: 'linux', Architecture: 'amd64', Config: { Labels: { 'org.opencontainers.image.revision': identity.revision } } }]);
  };
  try {
    const options = { identify: async () => identity, run };
    const manifest = await exportAcceptanceImage('identity-api:owned', directory, options);
    assert.equal(manifest.imageId, imageId);
    assert.deepEqual((await readReport(resolve(directory, 'acceptance-api.json'))).identity, identity);
    assert.equal((await loadAcceptanceImage(directory, options)).imageId, imageId);
    assert.deepEqual(calls.at(-1), ['image', 'inspect', imageId]);
    calls.length = 0;
    await writeFile(resolve(directory, 'acceptance-api.tar'), 'tampered-image');
    await assert.rejects(loadAcceptanceImage(directory, options), /checksum mismatch/);
    assert.equal(calls.length, 0, 'A checksum failure must never load an image');
    await writeFile(resolve(directory, 'acceptance-api.tar'), 'owned-image-archive');
    await assert.rejects(loadAcceptanceImage(directory, { ...options, identify: async () => ({ ...identity, source: 'e'.repeat(64) }) }), /identity mismatch/);
    assert.equal(calls.length, 0, 'A source/generation failure must never load an image');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
