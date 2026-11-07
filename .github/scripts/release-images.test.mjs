import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  PLATFORM,
  REPOSITORY,
  SOURCE,
  RegistryError,
  assertImage,
  compareStableVersions,
  computeMetadata,
  createRegistry,
  exportImage,
  formatSummary,
  main,
  parseVersion,
  publishImages,
  runCommand,
  verifyReleaseTag,
} from './release-images.mjs';

const REVISION = 'a'.repeat(40);
const OTHER_REVISION = 'b'.repeat(40);
const VERSION = '1.10.0';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const digest = (value) => `sha256:${hash(value)}`;
const envFor = (overrides = {}) => ({
  GITHUB_REPOSITORY: REPOSITORY,
  GITHUB_EVENT_NAME: 'push',
  GITHUB_REF: `refs/tags/v${VERSION}`,
  GITHUB_SHA: REVISION,
  GITHUB_RUN_ID: '1234',
  GITHUB_ACTOR: 'test-actor',
  GITHUB_TOKEN: 'test-token',
  ...overrides,
});
const imageFor = (kind, version = VERSION) => ({
  imageId: digest(`${kind}-${version}-config`),
  digest: digest(`${kind}-${version}-manifest`),
  platform: PLATFORM,
  source: SOURCE,
  revision: REVISION,
  version,
});
const inspectDocument = (image) => ({
  Id: image.imageId,
  Os: image.platform.split('/')[0],
  Architecture: image.platform.split('/')[1],
  Config: {
    Labels: {
      'org.opencontainers.image.source': image.source,
      'org.opencontainers.image.revision': image.revision,
      'org.opencontainers.image.version': image.version,
    },
  },
});
const response = (value, status = 200, headers = {}) =>
  new Response(
    typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value),
    { status, headers }
  );
const registryError = (status = 403, code = 'DENIED') =>
  new RegistryError('test', { status, body: Buffer.from(JSON.stringify({ errors: [{ code }] })) });

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'identity-release-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function fixture(t, { version = VERSION, env: overrides = {} } = {}) {
  const directory = await temporaryDirectory(t);
  const env = envFor({ GITHUB_REF: `refs/tags/v${version}`, ...overrides });
  const images = Object.fromEntries(['api', 'web'].map((kind) => [kind, imageFor(kind, version)]));
  const remote = new Map();
  const calls = [];
  const reports = [];
  const controls = {};
  for (const kind of ['api', 'web']) {
    const archive = Buffer.from(`tested archive for ${kind}`);
    const { digest: unused, ...image } = images[kind];
    await writeFile(join(directory, `${kind}.tar`), archive);
    await writeFile(
      join(directory, `${kind}.json`),
      JSON.stringify({
        kind,
        archive: `${kind}.tar`,
        sha256: hash(archive),
        ...image,
        runId: env.GITHUB_RUN_ID,
      })
    );
  }
  const run = async (command, args, options) => {
    assert.ok(options?.env);
    if (command === 'git') {
      assert.deepEqual(args, ['rev-parse', '--verify', 'HEAD^{commit}']);
      return `${REVISION}\n`;
    }
    if (command === process.execPath) {
      assert.ok(args[0].endsWith('smoke-image.mjs'));
      const [, kind, reference] = args;
      assert.equal(reference, `ghcr.io/hatefsystems/identity-${kind}@${images[kind].digest}`);
      calls.push({ action: 'smoke', kind });
      if (controls.failSmoke === kind) throw new Error('smoke failure');
      return '';
    }
    assert.equal(command, 'docker');
    if (args[0] === '--config') {
      assert.deepEqual(args.slice(2, 6), ['image', 'pull', '--platform', PLATFORM]);
      assert.deepEqual(await readdir(args[1]), []);
      const kind = args[6].includes('identity-api') ? 'api' : 'web';
      assert.ok(
        [
          `ghcr.io/hatefsystems/identity-${kind}:${version}`,
          `ghcr.io/hatefsystems/identity-${kind}@${images[kind].digest}`,
        ].includes(args[6])
      );
      calls.push({ action: 'anonymous-pull', kind, directory: args[1] });
      if (controls.failAnonymousPull === kind) throw new Error('anonymous pull failure');
      return '';
    }
    assert.equal(args[0], 'image');
    const action = args[1];
    if (action === 'inspect') {
      const reference = args[2];
      let image = Object.values(images).find((candidate) => candidate.imageId === reference);
      if (!image) image = images[reference.includes('identity-api') ? 'api' : 'web'];
      if (controls.inspect) image = controls.inspect(image, reference);
      calls.push({ action, reference });
      return JSON.stringify([inspectDocument(image)]);
    }
    if (action === 'load') {
      assert.equal(args[2], '--input');
      calls.push({ action, path: args[3] });
      return '';
    }
    if (action === 'tag') {
      const kind = args[3].includes('identity-api') ? 'api' : 'web';
      assert.equal(args[2], images[kind].imageId);
      assert.equal(args[3], `ghcr.io/hatefsystems/identity-${kind}:${version}`);
      calls.push({ action, kind });
      return '';
    }
    if (action === 'push') {
      assert.equal(args[2], '--platform');
      assert.equal(args[3], PLATFORM);
      const kind = args[4].includes('identity-api') ? 'api' : 'web';
      assert.equal(args[4], `ghcr.io/hatefsystems/identity-${kind}:${version}`);
      calls.push({ action, kind });
      if (controls.failPush === kind) throw new Error('push failure');
      remote.set(`${kind}:${version}`, images[kind]);
      if (controls.failAfterPush === kind) throw new Error('push response lost');
      return '';
    }
    if (action === 'pull') {
      assert.equal(args[2], '--platform');
      assert.equal(args[3], PLATFORM);
      const kind = args[4].includes('identity-api') ? 'api' : 'web';
      assert.equal(args[4], `ghcr.io/hatefsystems/identity-${kind}@${images[kind].digest}`);
      calls.push({ action, kind });
      return '';
    }
    assert.fail(`Unexpected Docker operation: ${action}`);
  };
  const fetchImpl = async (url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    assert.equal(options.redirect, 'manual');
    calls.push({ action: 'github' });
    assert.equal(url, `https://api.github.com/repos/${REPOSITORY}/git/ref/tags/v${version}`);
    return response({
      ref: env.GITHUB_REF,
      object: { type: 'commit', sha: controls.tagRevision || REVISION },
    });
  };
  const registry = {
    async read(kind, reference, options = {}) {
      calls.push({ action: 'read', kind, reference, anonymous: Boolean(options.anonymous) });
      if (controls.readError) controls.readError(kind, reference, options);
      if (options.anonymous && controls.private === kind) throw registryError();
      if (reference.startsWith('sha256:')) {
        return (
          [...remote.entries()].find(
            ([key, image]) => key.startsWith(`${kind}:`) && image.digest === reference
          )?.[1] || null
        );
      }
      return remote.get(`${kind}:${reference}`) || null;
    },
    async promote(kind, image) {
      assert.equal(
        calls.filter((call) => call.action === 'smoke').length >= 2,
        true,
        'both digest smokes must precede latest'
      );
      calls.push({ action: 'promote', kind, digest: image.digest });
      if (controls.failPromote === kind) throw new Error('promotion failure');
      remote.set(`${kind}:latest`, image);
      if (controls.failAfterPromote === kind) throw new Error('promotion response lost');
    },
  };
  const execute = () =>
    publishImages(directory, {
      env,
      run,
      fetchImpl,
      registry,
      report: (summary) => reports.push(structuredClone(summary)),
    });
  return { directory, env, images, remote, calls, controls, reports, execute };
}

test('strict SemVer accepts stable/prerelease and Docker length boundaries', () => {
  for (const version of [
    '0.0.0',
    VERSION,
    '1.2.3-rc.1',
    '1.2.3-0',
    '1.2.3-01alpha.a-b',
    `1.2.3-${'a'.repeat(122)}`,
  ]) {
    assert.equal(parseVersion(version).version, version);
  }
  assert.equal(parseVersion(VERSION).stable, true);
  assert.equal(parseVersion('1.2.3-rc.1').stable, false);
  for (const version of [
    'v1.2.3',
    '1.2',
    '01.2.3',
    '1.02.3',
    '1.2.03',
    '1.2.3-01',
    '1.2.3-rc.01',
    '1.2.3+',
    '1.2.3+build',
    '1.2.3-rc+build',
    '1.2.3-',
    '1.2.3-rc..1',
    '1.2.3-a_b',
    ' 1.2.3',
    '1.2.3\n',
    '1.2.3\r\n',
    '1.2.3-\u00e9',
    `1.2.3-${'a'.repeat(123)}`,
  ]) {
    assert.throws(() => parseVersion(version), /Invalid release version/, version);
  }
});

test('stable comparisons are numerical and retain arbitrary integer precision', () => {
  assert.equal(compareStableVersions('1.10.0', '1.9.0'), 1);
  assert.equal(compareStableVersions('1.9.0', '1.10.0'), -1);
  assert.equal(compareStableVersions('1.10.0', '1.10.0'), 0);
  assert.equal(compareStableVersions('9007199254740993.0.0', '9007199254740992.0.0'), 1);
  assert.throws(() => compareStableVersions('1.2.3-rc.1', '1.2.3'), /stable/);
});

test('metadata allows only explicit canonical version-tag pushes', () => {
  assert.deepEqual(computeMetadata(envFor(), REVISION), {
    revision: REVISION,
    version: VERSION,
    source: SOURCE,
    release: true,
  });
  assert.equal(
    computeMetadata(envFor({ GITHUB_REF: 'refs/tags/v2.0.0-beta.1' }), REVISION).version,
    '2.0.0-beta.1'
  );
  for (const override of [
    { GITHUB_EVENT_NAME: 'pull_request' },
    { GITHUB_EVENT_NAME: 'pull_request_target' },
    { GITHUB_EVENT_NAME: 'workflow_dispatch' },
    { GITHUB_EVENT_NAME: 'release' },
    { GITHUB_REF: 'refs/heads/main' },
    { GITHUB_REF: `refs/heads/v${VERSION}` },
    { GITHUB_REF: `refs/tags/${VERSION}` },
    { GITHUB_REPOSITORY: 'fork/identity' },
    { GITHUB_REPOSITORY: undefined },
    { GITHUB_REPOSITORY: 'HatefSystems/identity' },
  ]) {
    const metadata = computeMetadata(envFor(override), REVISION);
    assert.equal(metadata.release, false, JSON.stringify(override));
    assert.equal(metadata.version, `sha-${REVISION}`);
  }
  assert.throws(
    () => computeMetadata(envFor({ GITHUB_REF: 'refs/tags/v1.02.3' }), REVISION),
    /Invalid release version/
  );
  assert.equal(
    computeMetadata(
      envFor({ GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/tags/vbad' }),
      REVISION
    ).release,
    false
  );
  assert.throws(() => computeMetadata(envFor(), `${REVISION}\n`), /full commit SHA/);
  assert.throws(
    () => computeMetadata(envFor({ GITHUB_REPOSITORY: 'owner/repo\nrelease=true' }), REVISION),
    /repository name/
  );
});

test('metadata CLI writes the four integration outputs with no token', async (t) => {
  const directory = await temporaryDirectory(t);
  const env = envFor({ GITHUB_OUTPUT: join(directory, 'outputs') });
  const logged = [];
  t.mock.method(console, 'log', (value) => logged.push(value));
  await main(['metadata'], env, { run: async () => `${REVISION}\n` });
  assert.equal(
    await readFile(env.GITHUB_OUTPUT, 'utf8'),
    `revision=${REVISION}\nversion=${VERSION}\nsource=${SOURCE}\nrelease=true\n`
  );
  assert.deepEqual(JSON.parse(logged[0]), computeMetadata(env, REVISION));
  assert.equal(logged[0].includes(env.GITHUB_TOKEN), false);
});

test('live verification handles lightweight, nested annotated, and annotated-event SHAs', async () => {
  const first = 'c'.repeat(40);
  const second = 'd'.repeat(40);
  const env = envFor({ GITHUB_SHA: first });
  const fetchImpl = async (url) => {
    if (url.includes('/ref/tags/'))
      return response({ ref: env.GITHUB_REF, object: { type: 'tag', sha: first } });
    if (url.endsWith(first)) return response({ sha: first, object: { type: 'tag', sha: second } });
    if (url.endsWith(second))
      return response({ sha: second, object: { type: 'commit', sha: REVISION } });
    assert.fail('Unexpected GitHub endpoint');
  };
  await verifyReleaseTag(computeMetadata(env, REVISION), env, fetchImpl);
  await verifyReleaseTag(computeMetadata(envFor(), REVISION), envFor(), async () =>
    response({ ref: envFor().GITHUB_REF, object: { type: 'commit', sha: REVISION } })
  );
});

test('live verification rejects a moved tag, event mismatch, inaccessible ref, and tag cycles', async () => {
  const env = envFor();
  const metadata = computeMetadata(env, REVISION);
  await assert.rejects(
    verifyReleaseTag(metadata, env, async () =>
      response({ ref: env.GITHUB_REF, object: { type: 'commit', sha: OTHER_REVISION } })
    ),
    /moved/
  );
  await assert.rejects(
    verifyReleaseTag(metadata, { ...env, GITHUB_SHA: OTHER_REVISION }, async (url) =>
      url.includes('/ref/')
        ? response({ ref: env.GITHUB_REF, object: { type: 'commit', sha: REVISION } })
        : response({ sha: OTHER_REVISION, object: { type: 'commit', sha: OTHER_REVISION } })
    ),
    /Event commit/
  );
  await assert.rejects(
    verifyReleaseTag(metadata, env, async () => response({}, 403)),
    /HTTP 403/
  );
  await assert.rejects(
    verifyReleaseTag(metadata, env, async (url) =>
      url.includes('/ref/')
        ? response({ ref: env.GITHUB_REF, object: { type: 'tag', sha: OTHER_REVISION } })
        : response({ sha: OTHER_REVISION, object: { type: 'tag', sha: OTHER_REVISION } })
    ),
    /resolve to a commit/
  );
  await assert.rejects(
    verifyReleaseTag(metadata, { ...env, GITHUB_TOKEN: '' }, async () =>
      assert.fail('No unauthenticated fallback')
    ),
    /GITHUB_TOKEN/
  );
});

test('export saves the inspected immutable ID and records archive provenance', async (t) => {
  const directory = await temporaryDirectory(t);
  for (const kind of ['api', 'web']) {
    const image = imageFor(kind);
    const commands = [];
    const run = async (command, args) => {
      commands.push([command, ...args]);
      if (command === 'git') return REVISION;
      if (args[1] === 'inspect') return JSON.stringify([inspectDocument(image)]);
      assert.deepEqual(args.slice(0, 3), ['image', 'save', '--output']);
      assert.equal(args[4], image.imageId);
      await writeFile(args[3], `archive-${kind}`);
      return '';
    };
    const artifact = await exportImage(kind, `local-${kind}:ci`, directory, { env: envFor(), run });
    assert.deepEqual(artifact, {
      kind,
      archive: `${kind}.tar`,
      sha256: hash(`archive-${kind}`),
      imageId: image.imageId,
      platform: PLATFORM,
      source: SOURCE,
      revision: REVISION,
      version: VERSION,
      runId: '1234',
    });
    assert.deepEqual(JSON.parse(await readFile(join(directory, `${kind}.json`), 'utf8')), artifact);
    assert.equal(
      commands.some(
        (command) =>
          command.includes('push') || command.includes('build') || command.includes('login')
      ),
      false
    );
  }
});

test('export refuses nonrelease events and mismatched image labels/platform', async (t) => {
  const directory = await temporaryDirectory(t);
  await assert.rejects(
    exportImage('api', 'local:ci', directory, {
      env: envFor({ GITHUB_EVENT_NAME: 'workflow_dispatch' }),
      run: async (command) => {
        assert.equal(command, 'git');
        return REVISION;
      },
    }),
    /canonical repository/
  );
  for (const [key, value] of [
    ['version', '1.9.0'],
    ['revision', OTHER_REVISION],
    ['source', 'https://github.com/other/repo'],
    ['platform', 'linux/arm64'],
  ]) {
    await assert.rejects(
      exportImage('api', 'local:ci', directory, {
        env: envFor(),
        run: async (command, args) => {
          if (command === 'git') return REVISION;
          assert.equal(args[1], 'inspect');
          return JSON.stringify([inspectDocument({ ...imageFor('api'), [key]: value })]);
        },
      }),
      /mismatch|canonical OCI/
    );
  }
  await assert.rejects(exportImage('api', '--help', directory), /local image reference/);
});

test('publisher gate rejects noncanonical/non-tag/non-push events before network or Docker', async (t) => {
  for (const override of [
    { GITHUB_EVENT_NAME: 'workflow_dispatch' },
    { GITHUB_EVENT_NAME: 'pull_request' },
    { GITHUB_REF: 'refs/heads/main' },
    { GITHUB_REPOSITORY: 'fork/identity' },
    { GITHUB_RUN_ID: undefined },
    { GITHUB_REF: 'refs/tags/v1.2.3+metadata' },
  ]) {
    const f = await fixture(t, { env: override });
    await assert.rejects(f.execute(), /canonical repository|GITHUB_RUN_ID|Invalid release version/);
    assert.deepEqual(f.calls, []);
  }
});

test('moved tags are rejected before archives are loaded', async (t) => {
  const f = await fixture(t);
  f.controls.tagRevision = OTHER_REVISION;
  await assert.rejects(f.execute(), /moved/);
  assert.deepEqual(
    f.calls.map((call) => call.action),
    ['github']
  );
});

test('both archive hashes and current-run metadata are checked before any load', async (t) => {
  const mutations = [
    async (f) => writeFile(join(f.directory, 'web.tar'), 'tampered'),
    async (f) => rm(join(f.directory, 'web.tar')),
    async (f) => writeFile(join(f.directory, 'web.tar'), ''),
    ...[
      ['runId', '9999'],
      ['archive', '../web.tar'],
      ['revision', OTHER_REVISION],
      ['version', '1.9.0'],
      ['source', 'https://github.com/other/repo'],
    ].map(([key, value]) => async (f) => {
      const path = join(f.directory, 'web.json');
      const metadata = JSON.parse(await readFile(path, 'utf8'));
      await writeFile(path, JSON.stringify({ ...metadata, [key]: value }));
    }),
  ];
  for (const mutate of mutations) {
    const f = await fixture(t);
    await mutate(f);
    await assert.rejects(f.execute());
    assert.equal(
      f.calls.some((call) => call.action === 'load' || call.action === 'push'),
      false
    );
  }
});

test('loaded image ID must agree with archive metadata', async (t) => {
  const f = await fixture(t);
  f.controls.inspect = (image) => ({ ...image, imageId: digest('different image') });
  await assert.rejects(f.execute(), /imageId mismatch/);
  assert.equal(
    f.calls.some((call) => call.action === 'push'),
    false
  );
});

test('first publication loads both archives, pushes versions, digest-smokes, then promotes', async (t) => {
  const f = await fixture(t);
  const result = await f.execute();
  assert.deepEqual(
    f.calls.filter((call) => call.action === 'push').map((call) => call.kind),
    ['api', 'web']
  );
  assert.deepEqual(
    f.calls.filter((call) => call.action === 'promote').map((call) => call.kind),
    ['api', 'web']
  );
  const firstPush = f.calls.findIndex((call) => call.action === 'push');
  assert.equal(f.calls.slice(0, firstPush).filter((call) => call.action === 'load').length, 2);
  const firstPromotion = f.calls.findIndex((call) => call.action === 'promote');
  assert.equal(
    f.calls.slice(0, firstPromotion).filter((call) => call.action === 'smoke').length,
    2
  );
  for (const state of result.images) {
    assert.equal(state.oldLatest, 'absent');
    assert.equal(state.newLatest, f.images[state.kind].digest);
    assert.equal(state.aliasResult, 'advanced');
    assert.match(state.visibility, /^public:/);
  }
  const summary = formatSummary(result);
  assert.ok(summary.includes(`docker pull ghcr.io/hatefsystems/identity-api:${VERSION}`));
  assert.ok(
    summary.includes(`docker pull ghcr.io/hatefsystems/identity-web@${f.images.web.digest}`)
  );
  assert.ok(summary.includes(REVISION));
});

test('both existing version names are preflighted before any new version write', async (t) => {
  const f = await fixture(t);
  f.remote.set(`web:${VERSION}`, { ...f.images.web, imageId: digest('unrelated image') });
  await assert.rejects(f.execute(), /imageId mismatch/);
  assert.equal(
    f.calls.some((call) => call.action === 'push' || call.action === 'promote'),
    false
  );
});

test('identical versions are reused without rebuilding or pushing again', async (t) => {
  const f = await fixture(t);
  for (const kind of ['api', 'web']) f.remote.set(`${kind}:${VERSION}`, f.images[kind]);
  const result = await f.execute();
  assert.equal(
    f.calls.some((call) => call.action === 'push' || call.action === 'tag'),
    false
  );
  assert.equal(
    f.calls.filter((call) => call.action === 'pull' || call.action === 'smoke').length,
    4
  );
  assert.ok(result.images.every((image) => image.versionResult === 'reused; digest smoke passed'));
});

test('a partial version pair converges on retry without overwriting the first image', async (t) => {
  const f = await fixture(t);
  f.controls.failPush = 'web';
  await assert.rejects(f.execute(), /push failure/);
  assert.equal(f.reports[0].images[0].digest, f.images.api.digest);
  assert.equal(f.reports[0].images[1].versionResult, 'absent after failed push');
  assert.equal(
    f.calls.some((call) => call.action === 'promote'),
    false
  );
  delete f.controls.failPush;
  const result = await f.execute();
  assert.match(result.images[0].versionResult, /^reused/);
  assert.equal(f.calls.filter((call) => call.action === 'push' && call.kind === 'api').length, 1);
  assert.ok(result.images.every((image) => image.aliasResult === 'advanced'));
});

test('a lost push response reports observed state and retry reuses the published content', async (t) => {
  const f = await fixture(t);
  f.controls.failAfterPush = 'api';
  await assert.rejects(f.execute(), /push response lost/);
  assert.equal(f.reports[0].images[0].digest, f.images.api.digest);
  assert.match(f.reports[0].images[0].versionResult, /verification incomplete/);
  delete f.controls.failAfterPush;
  await f.execute();
  assert.equal(f.calls.filter((call) => call.action === 'push' && call.kind === 'api').length, 1);
});

test('a failed first push still reports the already-existing second version digest', async (t) => {
  const f = await fixture(t);
  f.remote.set(`web:${VERSION}`, f.images.web);
  f.controls.failPush = 'api';
  await assert.rejects(f.execute(), /push failure/);
  assert.equal(f.reports[0].images[1].digest, f.images.web.digest);
  assert.equal(f.reports[0].images[1].versionResult, 'existing; content verified');
});

test('partial alias updates record old/new digests and converge on retry', async (t) => {
  const f = await fixture(t);
  const old = imageFor('web', '1.9.0');
  f.remote.set('api:latest', imageFor('api', '1.9.0'));
  f.remote.set('web:latest', old);
  f.controls.failPromote = 'web';
  await assert.rejects(f.execute(), /promotion failure/);
  const failed = f.reports[0];
  assert.equal(failed.images[0].aliasResult, 'advanced');
  assert.equal(failed.images[0].newLatest, f.images.api.digest);
  assert.equal(failed.images[1].oldLatest, old.digest);
  assert.equal(failed.images[1].newLatest, old.digest);
  assert.match(formatSummary(failed), /partial registry state/);
  delete f.controls.failPromote;
  const result = await f.execute();
  assert.equal(result.images[0].aliasResult, 'reused');
  assert.equal(result.images[1].aliasResult, 'advanced');
  assert.equal(
    f.calls.filter((call) => call.action === 'promote' && call.kind === 'api').length,
    1
  );
  assert.equal(f.calls.filter((call) => call.action === 'push').length, 2);
});

test('lost promotion response is not rolled back and an equal alias is reused next time', async (t) => {
  const f = await fixture(t);
  f.controls.failAfterPromote = 'web';
  await assert.rejects(f.execute(), /promotion response lost/);
  assert.equal(f.reports[0].images[1].newLatest, f.images.web.digest);
  delete f.controls.failAfterPromote;
  const result = await f.execute();
  assert.ok(result.images.every((image) => image.aliasResult === 'reused'));
  assert.equal(f.calls.filter((call) => call.action === 'promote').length, 2);
});

test('either newer stable alias leaves BOTH aliases untouched', async (t) => {
  const f = await fixture(t, { version: '1.9.0' });
  f.remote.set('api:latest', imageFor('api', '1.10.0'));
  f.remote.set('web:latest', imageFor('web', '1.8.0'));
  const result = await f.execute();
  assert.equal(
    f.calls.some((call) => call.action === 'promote'),
    false
  );
  assert.equal(f.remote.get('web:latest').version, '1.8.0');
  assert.ok(result.images.every((image) => image.aliasResult.includes('newer stable')));
});

test('prereleases publish exact versions but never inspect or change latest', async (t) => {
  const f = await fixture(t, { version: '2.0.0-rc.1' });
  f.controls.readError = (kind, reference) => {
    assert.notEqual(reference, 'latest');
  };
  const result = await f.execute();
  assert.equal(f.calls.filter((call) => call.action === 'push').length, 2);
  assert.equal(
    f.calls.some((call) => call.action === 'promote'),
    false
  );
  assert.ok(result.images.every((image) => image.aliasResult === 'unchanged: prerelease'));
});

test('unknown latest metadata or equal-version conflicting content fails closed for both aliases', async (t) => {
  for (const override of [
    { version: 'unknown' },
    { version: '1.10.0-rc.1' },
    { imageId: digest('different latest') },
    { digest: digest('different manifest') },
    { source: 'https://github.com/unrelated/repo' },
  ]) {
    const f = await fixture(t);
    f.remote.set('api:latest', imageFor('api', '1.9.0'));
    f.remote.set('web:latest', { ...f.images.web, ...override });
    await assert.rejects(f.execute());
    assert.equal(
      f.calls.some((call) => call.action === 'promote'),
      false
    );
    assert.equal(f.remote.get('api:latest').version, '1.9.0');
  }
});

test('registry failures and smoke failures never permit alias updates', async (t) => {
  for (const stage of ['version', 'latest', 'anonymous', 'smoke']) {
    const f = await fixture(t);
    if (stage === 'smoke') f.controls.failSmoke = 'web';
    else
      f.controls.readError = (kind, reference, options) => {
        if (
          kind === 'web' &&
          ((stage === 'version' && reference === VERSION) ||
            (stage === 'latest' && reference === 'latest') ||
            (stage === 'anonymous' && options.anonymous))
        )
          throw registryError(503, 'UNKNOWN');
      };
    await assert.rejects(f.execute());
    assert.equal(
      f.calls.some((call) => call.action === 'promote'),
      false
    );
    if (stage === 'version')
      assert.equal(
        f.calls.some((call) => call.action === 'push'),
        false
      );
  }
});

test('new private packages get an explicit administrator warning, not a false public claim', async (t) => {
  const f = await fixture(t);
  f.controls.private = 'api';
  const result = await f.execute();
  assert.match(result.images[0].visibility, /^not public: administrator bootstrap/);
  assert.match(result.images[1].visibility, /^public:/);
  assert.match(formatSummary(result), /Newly created GHCR packages start private/);
});

test('public verification uses fresh Docker credentials and cleans them on failure', async (t) => {
  const f = await fixture(t);
  f.controls.failAnonymousPull = 'web';
  await assert.rejects(f.execute(), /anonymous pull failure/);
  assert.equal(f.calls.filter((call) => call.action === 'promote').length, 0);
  const pulls = f.calls.filter((call) => call.action === 'anonymous-pull');
  assert.equal(pulls.length, 3);
  for (const pull of pulls) {
    await assert.rejects(lstat(pull.directory), { code: 'ENOENT' });
  }
});

test('registry treats explicit MANIFEST_UNKNOWN as absence even for first publication', async () => {
  const calls = [];
  const registry = createRegistry(envFor(), async (url, options) => {
    calls.push({ url, options });
    if (url.includes('/token?')) {
      assert.equal(
        new URL(url).searchParams.get('scope'),
        'repository:hatefsystems/identity-api:pull,push'
      );
      assert.equal(
        options.headers.Authorization,
        `Basic ${Buffer.from('test-actor:test-token').toString('base64')}`
      );
      return response({ token: 'registry-test-token' });
    }
    return response({ errors: [{ code: 'MANIFEST_UNKNOWN' }] }, 404);
  });
  assert.equal(await registry.read('api', VERSION), null);
  assert.equal(calls.length, 2);
  assert.ok(
    calls.every(
      (call) => call.options.signal instanceof AbortSignal && call.options.redirect === 'manual'
    )
  );
});

test('registry never treats authentication, ambiguous absence, malformed errors, or outages as absence', async () => {
  for (const [status, errors] of [
    [401, [{ code: 'UNAUTHORIZED' }]],
    [403, [{ code: 'DENIED' }]],
    [404, [{ code: 'DENIED' }]],
    [404, [{ code: 'NAME_UNKNOWN' }]],
    [404, []],
    [404, [{ code: 'MANIFEST_UNKNOWN' }, { code: 'bad' }]],
    [429, [{ code: 'TOOMANYREQUESTS' }]],
    [500, [{ code: 'UNKNOWN' }]],
  ]) {
    const registry = createRegistry(envFor(), async (url) =>
      url.includes('/token?')
        ? response({ token: 'registry-test-token' })
        : response({ errors }, status)
    );
    await assert.rejects(registry.read('api', VERSION), RegistryError);
  }
  let count = 0;
  await assert.rejects(
    createRegistry(envFor(), async () => {
      count++;
      return response({ errors: [{ code: 'DENIED', message: 'test-token' }] }, 403);
    }).read('api', VERSION),
    (error) => error instanceof RegistryError && !error.message.includes('test-token')
  );
  assert.equal(count, 1, 'token denial cannot trigger a manifest fallback');
  await assert.rejects(
    createRegistry(envFor(), async () => {
      throw new Error('network failure containing test-token');
    }).read('api', VERSION),
    (error) => !error.message.includes('test-token')
  );
});

function registryDocuments() {
  const config = Buffer.from(
    JSON.stringify({
      os: 'linux',
      architecture: 'amd64',
      config: inspectDocument(imageFor('api')).Config,
    })
  );
  const manifest = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: { digest: digest(config) },
      layers: [{ digest: digest('layer') }],
    })
  );
  return { config, manifest, manifestDigest: digest(manifest) };
}

test('registry verifies manifests/config IDs and follows CDN redirects without credentials', async () => {
  const { config, manifest, manifestDigest } = registryDocuments();
  const registry = createRegistry(envFor(), async (url, options) => {
    if (url.includes('/token?')) return response({ token: 'registry-test-token' });
    if (url.includes('/manifests/'))
      return response(manifest, 200, { 'docker-content-digest': manifestDigest });
    if (url.includes('/blobs/'))
      return response('', 307, { location: 'https://cdn.example/config' });
    assert.equal(url, 'https://cdn.example/config');
    assert.deepEqual(options.headers, {});
    return response(config);
  });
  const image = await registry.read('api', manifestDigest);
  assert.equal(image.digest, manifestDigest);
  assert.equal(image.imageId, digest(config));
  assertImage(image);
});

test('registry rejects incorrect content hashes, unexpected indexes, and unsafe redirects', async () => {
  const { config, manifest, manifestDigest } = registryDocuments();
  for (const mode of ['manifest-hash', 'config-hash', 'index', 'redirect']) {
    const registry = createRegistry(envFor(), async (url) => {
      if (url.includes('/token?')) return response({ token: 'registry-test-token' });
      if (url.includes('/manifests/')) {
        if (mode === 'index')
          return response({
            schemaVersion: 2,
            mediaType: 'application/vnd.oci.image.index.v1+json',
            manifests: [],
          });
        return response(manifest, 200, {
          'docker-content-digest': mode === 'manifest-hash' ? digest('wrong') : manifestDigest,
        });
      }
      if (mode === 'redirect') return response('', 307, { location: 'http://cdn.example/config' });
      return response(mode === 'config-hash' ? Buffer.from('{}') : config);
    });
    await assert.rejects(registry.read('api', VERSION), /digest|single-platform|Unsafe/);
  }
});

test('anonymous verification obtains only an anonymous pull token', async () => {
  const { config, manifest } = registryDocuments();
  const registry = createRegistry(envFor(), async (url, options) => {
    if (url.includes('/token?')) {
      assert.deepEqual(options.headers, {});
      assert.equal(
        new URL(url).searchParams.get('scope'),
        'repository:hatefsystems/identity-api:pull'
      );
      return response({ token: 'anonymous-token' });
    }
    assert.equal(options.headers.Authorization, 'Bearer anonymous-token');
    return response(url.includes('/manifests/') ? manifest : config);
  });
  assertImage(await registry.read('api', VERSION, { anonymous: true }));
});

test('latest promotion copies exact manifest bytes without rebuilding/reserializing', async () => {
  const { manifest, manifestDigest } = registryDocuments();
  let promoted = false;
  const registry = createRegistry(envFor(), async (url, options) => {
    if (url.includes('/token?')) return response({ token: 'registry-test-token' });
    assert.equal(url, 'https://ghcr.io/v2/hatefsystems/identity-api/manifests/latest');
    assert.equal(options.method, 'PUT');
    assert.equal(options.body, manifest);
    promoted = true;
    return response('', 201, { 'docker-content-digest': manifestDigest });
  });
  await registry.promote('api', {
    manifest,
    digest: manifestDigest,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
  });
  assert.equal(promoted, true);
});

test('HTTP response sizes are bounded and invalid credentials never appear in errors', async () => {
  await assert.rejects(
    createRegistry(envFor(), async () => response('x'.repeat(4 * 1024 * 1024 + 1))).read(
      'api',
      VERSION
    ),
    /response limit/
  );
});

test('child processes use literal arguments, scrub workflow tokens, and enforce output/time limits', async () => {
  const literal = 'a; $(echo not-a-shell) & b';
  const output = await runCommand(
    process.execPath,
    [
      '-e',
      'process.stdout.write(JSON.stringify([process.argv[1],process.env.GITHUB_TOKEN,process.env.GH_TOKEN]))',
      literal,
    ],
    {
      env: {
        ...process.env,
        GITHUB_TOKEN: 'secret-test-value',
        GH_TOKEN: 'another-secret-test-value',
      },
    }
  );
  assert.deepEqual(JSON.parse(output), [literal, null, null]);
  await assert.rejects(
    runCommand(process.execPath, ['-e', 'process.stdout.write("x".repeat(1024))'], {
      maxBuffer: 32,
    }),
    /output limit/
  );
  await assert.rejects(
    runCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeout: 100 }),
    /timed out/
  );
});

test('importing the module does not execute its CLI', async () => {
  const url = new URL('./release-images.mjs', import.meta.url).href;
  assert.equal(
    await runCommand(process.execPath, [
      '--input-type=module',
      '-e',
      `await import(${JSON.stringify(url)}); process.stdout.write('import-safe')`,
    ]),
    'import-safe'
  );
});
