import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { galleryEnvironment, generateGallery, galleryLocales, galleryThemes, galleryDevices, galleryRoutes, galleryViews,
  galleryJobs, galleryDetails, galleryProgress, validateGalleryManifest, galleryHTML, escapeGalleryHTML, galleryHelperInputs } from './generate-page-gallery.mjs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Node test workers add diagnostic flags. The mock-only launcher suite runs in
// a clean child, retaining the production launcher's stricter runtime guard.
if (process.execArgv.some(value => /--inspect|--prof|--trace/.test(value))) {
  const childEnvironment = { ...process.env };
  delete childEnvironment.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    encoding: 'utf8', env: childEnvironment,
  });
  assert.equal(child.status, 0, child.stdout + child.stderr);
  console.log(child.stdout);
} else {
const original = { DEBUG: '*', NODE_DEBUG: 'child_process', NODE_DEBUG_NATIVE: '*', PWDEBUG: '1', NX_PROJECT_NAME: 'ui', KEEP: 'yes', PAGE_GALLERY_BROWSER_ACCEPTANCE: 'passed' };
const sanitized = galleryEnvironment(original);
for (const key of ['DEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'PWDEBUG', 'NX_PROJECT_NAME']) assert.equal(sanitized[key], undefined);
assert.equal(original.DEBUG, '*'); assert.equal(sanitized.KEEP, 'yes');
assert.equal(sanitized.NX_DAEMON, 'false'); assert.equal(sanitized.CI, 'true');

async function scenario(operation) {
  const root = await mkdtemp(resolve(tmpdir(), 'gallery-launcher-test-'));
  try {
    for (const path of galleryHelperInputs) {
      await mkdir(resolve(root, path, '..'), { recursive: true });
      await writeFile(resolve(root, path), '');
    }
    await mkdir(resolve(root, 'apps/identity-api'), { recursive: true });
    await writeFile(resolve(root, 'apps/identity-api/go.mod'), 'go 1.26.5\n');
    await mkdir(resolve(root, 'node_modules/nx'), { recursive: true });
    await writeFile(resolve(root, 'node_modules/nx/package.json'), '{}');
    await operation(root);
  } finally { await rm(root, { recursive: true, force: true }); }
}

function completedManifest(runId = '123-456') {
  const jobs = galleryJobs().map(job => ({ ...job, status: 'captured', masked: false, demoValues: true, decoded: true,
    sourceAppearance: job.mode === 'viewport' ? 'system-os' : 'app-preference', width: job.viewport.width, height: job.viewport.height }));
  const details = galleryDetails().map(job => ({ ...job, status: 'not-needed', needed: false }));
  const manifest = { version: 2, runId, sourceSHA: 'a'.repeat(40), status: 'complete', cleanup: 'completed',
    rendering: 'offline-sanitized-synthetic-clone', acceptancePrerequisite: 'parent-confirmed-browser-pass', jobs, details,
    expectedViews: galleryViews.length, expectedPNGs: jobs.length, capturedPNGs: jobs.length, verifiedPNGs: jobs.length,
    detailPNGs: 0, findings: [] };
  manifest.progress = galleryProgress(manifest);
  return manifest;
}

function fakeExecutor(root, calls, { failCapture = false, failReview = false, interrupt = false } = {}) {
  return async (executable, args, options) => {
    calls.push({ executable, args, options });
    assert.equal(options.cwd, root);
    assert.equal(options.env.DEBUG, undefined); assert.equal(options.env.PWDEBUG, undefined);
    if (executable === 'npm' && args[0] === '--version') return '11.0.0';
    if (executable === 'git') return root;
    if (executable === 'go') return 'go version go1.26.5 linux/amd64';
    if (executable === 'openssl') return 'OpenSSL 3.0.13';
    if (executable === 'docker' && args[0] === 'context') return '{"Host":"unix:///var/run/docker.sock"}';
    if (args[0]?.endsWith('/page-gallery.mjs')) {
      assert.equal(options.env.PAGE_GALLERY_DEFER_LATEST, '1');
      if (failCapture) throw new Error('DO-NOT-PRINT-PRIVATE-DIAGNOSTICS');
      if (interrupt) { process.emit('SIGTERM'); throw new Error('Interrupted test'); }
      const directory = resolve(root, 'test-output/page-gallery', options.env.PAGE_GALLERY_RUN_ID);
      await mkdir(directory);
      await writeFile(resolve(directory, 'manifest.json'), JSON.stringify(completedManifest(options.env.PAGE_GALLERY_RUN_ID)));
    }
    if (args[0]?.endsWith('/page-gallery-review.mjs')) {
      if (failReview) throw new Error('DO-NOT-PRINT-PRIVATE-DIAGNOSTICS');
      const path = resolve(root, 'test-output/page-gallery', args[1], 'manifest.json');
      const manifest = JSON.parse(await readFile(path, 'utf8'));
      manifest.review = { automated: 'passed', grayCoverCheck: 'passed', imageChecks: manifest.expectedPNGs,
        offlineGallery: 'passed', unexpectedNetwork: 0, privateArtifactInputs: 'readable-synthetic-demo-values-only', progress: manifest.progress };
      await writeFile(path, JSON.stringify(manifest));
    }
    return '';
  };
}

await scenario(async root => {
  const calls = [];
  await generateGallery({ root, environment: original, execute: fakeExecutor(root, calls), checkOnly: true, log() {} });
  assert(!calls.some(call => call.args.includes('run-many')));
  await assert.rejects(stat(resolve(root, 'test-output')), { code: 'ENOENT' });
  await assert.rejects(stat(resolve(root, '.kilo')), { code: 'ENOENT' });
});

await scenario(async root => {
  const calls = [];
  const result = await generateGallery({ root, environment: original, execute: fakeExecutor(root, calls), log() {} });
  assert.match(result.runID, /^\d+-\d+$/); assert.equal(result.images, galleryJobs().length);
  const builds = calls.filter(call => call.args.includes('run-many'));
  assert.equal(builds.length, 2); assert(builds.every(call => call.args.includes('--skipNxCache')));
  assert.equal(calls.filter(call => call.args[0]?.endsWith('/page-gallery.mjs')).length, 1);
  assert((await readFile(resolve(root, 'test-output/page-gallery/index.html'), 'utf8')).includes(result.runID + '/index.html'));
  await assert.rejects(stat(resolve(root, 'test-output/page-gallery/.generation.lock')), { code: 'ENOENT' });
});

for (const mode of [{ failCapture: true }, { failReview: true }, { interrupt: true }]) await scenario(async root => {
  await mkdir(resolve(root, 'test-output/page-gallery'), { recursive: true });
  const latest = resolve(root, 'test-output/page-gallery/index.html');
  await writeFile(latest, 'previous validated gallery');
  const calls = [];
  await assert.rejects(generateGallery({ root, environment: original,
    execute: fakeExecutor(root, calls, mode), log() {} }), error => {
    assert(!error.message.includes('PRIVATE'));
    assert(mode.interrupt ? error.exitCode === 130 : error.exitCode === 1);
    return true;
  });
  assert.equal(await readFile(latest, 'utf8'), 'previous validated gallery');
  await assert.rejects(stat(resolve(root, 'test-output/page-gallery/.generation.lock')), { code: 'ENOENT' });
});

await scenario(async root => {
  await mkdir(resolve(root, 'test-output/page-gallery'), { recursive: true });
  const lock = resolve(root, 'test-output/page-gallery/.generation.lock');
  await writeFile(lock, 'another generator owns this');
  const calls = [];
  await assert.rejects(generateGallery({ root, environment: original, execute: fakeExecutor(root, calls), log() {} }), /Another run or interrupted lock/);
  assert.equal(await readFile(lock, 'utf8'), 'another generator owns this');
  assert(!calls.some(call => call.args.includes('run-many')));
});

console.log('Gallery launcher passed: environment isolation, check-only, fresh builds, exact run validation, failure/interrupt cleanup, preserved latest link, and foreign-lock protection.');

test('formal browser acknowledgement is required before build/capture/publication', async () => scenario(async root => {
  const calls = [];
  const environment = { ...original }; delete environment.PAGE_GALLERY_BROWSER_ACCEPTANCE;
  await assert.rejects(generateGallery({ root, environment, execute: fakeExecutor(root, calls), log() {} }), /formal browser acceptance prerequisite/);
  assert(!calls.some(call => call.args.includes('run-many') || call.args[0]?.endsWith('/page-gallery.mjs')));
  await assert.rejects(stat(resolve(root, 'test-output')), { code: 'ENOENT' });
}));

test('prerequisite failures remain non-capturing and suppress raw diagnostics', async () => {
  for (const [executable, value, stage] of [
    ['go', 'go version go1.26.4 linux/amd64', 'Go runtime'],
    ['go', 'go version go1.25.9 linux/amd64', 'Go runtime'],
    ['openssl', 'OpenSSL 1.1.1', 'OpenSSL runtime'],
    ['docker', '{"Host":"tcp://private-docker.example:2375"}', 'local Docker endpoint'],
  ]) await scenario(async root => {
    const calls = [], execute = fakeExecutor(root, calls);
    await assert.rejects(generateGallery({ root, environment: original, checkOnly: true, log() {},
      execute: (command, args, options) => command === executable ? value : execute(command, args, options),
    }), error => error.message === `Generation failed during ${stage}.`);
    assert(!calls.some(call => call.args.includes('run-many') || call.args[0]?.endsWith('/page-gallery.mjs')));
    await assert.rejects(stat(resolve(root, 'test-output')), { code: 'ENOENT' });
  });
});

test('check accepts a newer Go toolchain and rejects a missing tracked helper without .kilo', async () => scenario(async root => {
  const calls = [], execute = fakeExecutor(root, calls);
  await generateGallery({ root, environment: original, checkOnly: true, log() {},
    execute: (command, args, options) => command === 'go' ? 'go version go1.27.3 linux/amd64' : execute(command, args, options),
  });
  await rm(resolve(root, '.github/scripts/release-images.mjs'));
  await assert.rejects(generateGallery({ root, environment: original, execute, checkOnly: true, log() {} }), /gallery helper inputs/);
  await assert.rejects(stat(resolve(root, '.kilo')), { code: 'ENOENT' });
}));

test('declared matrix derives current state/locale/core/detail totals, including genuine short reviews', () => {
  const jobs = galleryJobs(), details = galleryDetails(jobs), progress = galleryProgress({ jobs, details });
  assert.equal(galleryRoutes.length, 20);
  assert.equal(new Set(galleryViews.map(view => view.id)).size, galleryViews.length);
  assert.equal(progress.expectedCorePNGs, galleryViews.reduce((sum, view) => sum + view.devices.length * galleryThemes.length * galleryLocales.length, 0));
  assert.equal(progress.declaredDetailPNGs, galleryViews.filter(view => view.detail).reduce((sum, view) => sum + view.devices.length * galleryThemes.length * galleryLocales.length, 0));
  for (const locale of galleryLocales) {
    assert.equal(progress.locales[locale].expectedStates, galleryViews.length);
    assert.equal(progress.locales[locale].expectedCorePNGs, jobs.filter(job => job.locale === locale).length);
    assert.equal(progress.locales[locale].declaredDetailPNGs, details.filter(job => job.locale === locale).length);
    assert.equal(progress.locales[locale].capturedStates, 0);
  }
  for (const id of ['dashboard-navigation-closed', 'dashboard-navigation-open', 'admin-navigation-open', 'admin-users-table-view',
    'admin-audit-table-view', 'admin-legal-holds-table-view', 'admin-legal-attribution-table-view', 'admin-user-moderation-enabled',
    'register-native-input', 'register-sms-native-digits', 'security-recovery-code-viewer', 'profile-conflict', 'privacy-deletion-enabled', 'not-found'])
    assert(galleryViews.some(view => view.id === id));
  for (const view of galleryViews.filter(view => view.devices.includes('short'))) {
    assert.equal(view.mode, 'viewport'); assert.equal(view.surface, 'admin');
    assert.deepEqual(galleryDevices.short, { width: 320, height: 256 });
  }
  assert(galleryRoutes.filter(([id]) => ['forgot-password', 'reset-password', 'verify-totp'].includes(id)).every(([, , heading]) => heading.endsWith('unavailable')));
  console.log(JSON.stringify({ galleryInventory: progress }));
});

test('current namespace headings and explicit supplementary scenarios match the declared inventory', async () => {
  const { setBrowserLocale, localizedText } = await import('../../.github/scripts/browser-localization.mjs');
  const sources = (await Promise.all(['portal', 'account', 'admin', 'registration'].map(name =>
    readFile(new URL(`./page-gallery-${name}.mjs`, import.meta.url), 'utf8')))).join('\n');
  for (const view of galleryViews.filter(view => view.state !== 'baseline')) assert(sources.includes(`'${view.id}'`), `Missing explicit scenario ${view.id}`);
  setBrowserLocale('fa-IR');
  try { for (const view of galleryViews) assert.notEqual(localizedText(view.heading), view.heading, `Untranslated current heading ${view.heading}`); }
  finally { setBrowserLocale('en'); }
  const admin = await readFile(new URL('./page-gallery-admin.mjs', import.meta.url), 'utf8');
  const declared = /const stateIDs = \[([\s\S]*?)\];/.exec(admin)[1].match(/'[^']+'/g).map(value => value.slice(1, -1));
  assert.deepEqual(declared.sort(), galleryViews.filter(view => view.surface === 'admin').map(view => view.id).sort());
});

test('completed manifests reject missing, duplicate, mismatched, injected or private capture metadata', () => {
  const manifest = completedManifest();
  assert.equal(validateGalleryManifest(manifest, { complete: true }).expectedStates, galleryViews.length);
  for (const mutate of [
    value => value.jobs.pop(), value => { value.jobs[1] = { ...value.jobs[0] }; },
    value => { value.jobs[0].locale = 'invalid'; }, value => { value.jobs[0].viewport.width++; },
    value => { value.jobs[0].synthetic = false; }, value => { value.jobs[0].sourceAppearance = 'injected-class'; },
    value => { value.jobs[0].privateToken = 'DO-NOT-PRINT-PRIVATE-DIAGNOSTICS'; },
    value => { value.jobs[0].path = '../escape.png'; }, value => { value.progress.locales.en.completedStates--; },
    value => { value.expectedPNGs++; }, value => { value.cleanup = 'failed'; },
    value => { value.details[0].status = 'captured'; value.details[0].decoded = true; },
  ]) {
    const invalid = structuredClone(manifest); mutate(invalid);
    assert.throws(() => validateGalleryManifest(invalid, { complete: true }));
  }
});

test('progress separately reports captured, decoded, blocked states and potential paired details', () => {
  const manifest = completedManifest(), first = manifest.jobs[0].id;
  for (const job of manifest.jobs.filter(job => job.id === first && job.locale === 'en')) job.decoded = false;
  manifest.jobs.find(job => job.id !== first && job.locale === 'en').status = 'blocked';
  const progress = galleryProgress(manifest);
  assert.equal(progress.locales.en.capturedStates, galleryViews.length - 1);
  assert.equal(progress.locales.en.completedStates, galleryViews.length - 2);
  assert.equal(progress.locales.en.blockedStates, 1);
  assert.equal(progress.locales['fa-IR'].completedStates, galleryViews.length);
});

test('required control details must be captured as full locale pairs and counted exactly', () => {
  const manifest = completedManifest();
  const first = manifest.details[0];
  const pair = manifest.details.filter(detail => detail.parent === first.parent && detail.device === first.device && detail.theme === first.theme);
  assert.equal(pair.length, galleryLocales.length);
  for (const detail of pair) Object.assign(detail, { status: 'captured', needed: true, masked: false, demoValues: true,
    decoded: true, sourceAppearance: detail.mode === 'viewport' ? 'system-os' : 'app-preference' });
  manifest.detailPNGs = pair.length;
  manifest.progress = galleryProgress(manifest);
  assert.equal(validateGalleryManifest(manifest, { complete: true }).requiredDetailPNGs, pair.length);
  for (const locale of galleryLocales) assert.equal(manifest.progress.locales[locale].requiredDetailPNGs, 1);
  pair[0].status = 'not-needed';
  manifest.progress = galleryProgress(manifest);
  assert.throws(() => validateGalleryManifest(manifest, { complete: true }));
});

test('offline HTML escapes host values and exercises inventory-derived route/state/locale/device/theme filters', () => {
  const manifest = completedManifest(), html = galleryHTML(manifest);
  assert(html.includes('synthetic clone') && html.includes('cannot prove native inputs'));
  assert.equal((html.match(/<section data-surface=/g) || []).length, galleryViews.length);
  assert.equal((html.match(/<img /g) || []).length, manifest.jobs.length);
  assert.equal(escapeGalleryHTML('<img src=x onerror="secret">&\''), '&lt;img src=x onerror=&quot;secret&quot;&gt;&amp;&#39;');
  const controls = Object.fromEntries(['surface', 'route', 'state', 'view', 'device', 'theme', 'locale'].map(id =>
    [id, { value: 'all', addEventListener(type, callback) { assert.equal(type, 'change'); this.callback = callback; } }]));
  const sections = galleryViews.map(view => ({ dataset: { surface: view.surface, route: view.route, state: view.state, view: view.id },
    pairs: view.devices.flatMap(device => galleryThemes.map(theme => ({ dataset: { device, theme },
      figures: galleryLocales.map(locale => ({ dataset: { locale } })), querySelectorAll() { return this.figures; } }))),
    querySelectorAll() { return this.pairs; } }));
  const document = { getElementById: id => controls[id], querySelectorAll: query => query === 'select' ? Object.values(controls) : sections };
  runInNewContext(/<script>([\s\S]*)<\/script>/.exec(html)[1], { document });
  controls.route.value = '/register'; controls.locale.value = 'fa-IR'; controls.theme.value = 'dark'; controls.route.callback();
  assert.equal(sections.filter(section => !section.hidden).length, galleryViews.filter(view => view.route === '/register').length);
  for (const section of sections) for (const pair of section.pairs) {
    assert.equal(pair.hidden, pair.dataset.theme !== 'dark');
    for (const figure of pair.figures) assert.equal(figure.hidden, figure.dataset.locale !== 'fa-IR');
  }
  controls.route.value = 'all'; controls.device.value = 'short'; controls.state.value = 'moderation-enabled'; controls.state.callback();
  assert.equal(sections.filter(section => !section.hidden).length, 1);
  assert.equal(sections.filter(section => !section.hidden).flatMap(section => section.pairs).filter(pair => !pair.hidden).length, 1);
  const invalid = structuredClone(manifest); invalid.jobs[0].route = '\"><img onerror=secret>';
  assert.throws(() => galleryHTML(invalid));
});

test('LIVE captures never inject appearance; substitutions only touch sanitized detached offline clones', async () => {
  for (const name of ['page-gallery.mjs', 'page-gallery-portal.mjs', 'page-gallery-account.mjs', 'page-gallery-admin.mjs', 'page-gallery-registration.mjs']) {
    const source = await readFile(new URL(name, import.meta.url), 'utf8');
    assert(!/classList\.toggle\(['"]dark|createElement\(['"]style|addStyleTag\(/.test(source), `LIVE appearance injection in ${name}`);
  }
  const renderer = await readFile(new URL('./page-gallery-demo.mjs', import.meta.url), 'utf8');
  assert(renderer.includes("root.setAttribute('data-gallery-synthetic', 'true')"));
  assert(renderer.includes('document.documentElement.cloneNode(true)'));
  assert(renderer.includes("bypassCSP: false, offline: true"));
  assert(renderer.includes('private diagnostics suppressed'));
});

test('runtime import closure and catalog/font inputs are versionable without local Kilo files', async () => {
  const { default: ts } = await import('typescript');
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const queue = [...galleryHelperInputs, 'tools/page-gallery/generate-page-gallery.mjs',
    'apps/web/messages/en.ts', 'apps/web/messages/fa-IR.ts', 'apps/web/app/fonts/Vazirmatn[wght].woff2'];
  const visited = new Set();
  while (queue.length) {
    const path = queue.pop();
    if (visited.has(path)) continue;
    visited.add(path);
    assert(!path.startsWith('../') && !path.includes('.kilo/'), `Local dependency: ${path}`);
    assert((await stat(resolve(root, path))).isFile(), `Missing dependency: ${path}`);
    const ignored = spawnSync('git', ['check-ignore', path], { cwd: root, stdio: 'ignore' });
    assert.equal(ignored.status, 1, `Ignored dependency: ${path}`);
    if (!path.startsWith('tools/page-gallery/')) {
      const tracked = spawnSync('git', ['ls-files', '--error-unmatch', path], { cwd: root, stdio: 'ignore' });
      assert.equal(tracked.status, 0, `Untracked external dependency: ${path}`);
    }
    if (!/\.(?:mjs|ts)$/.test(path)) continue;
    const source = await readFile(resolve(root, path), 'utf8');
    if (path.startsWith('tools/page-gallery/')) assert(!/\/tmp\/kilo|\/home\/|[A-Z]:\\/.test(source));
    const syntax = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
    const visit = node => {
      let specifier;
      if ((ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) || ts.isExportDeclaration(node)) specifier = node.moduleSpecifier;
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) specifier = node.arguments[0];
      if (specifier && ts.isStringLiteral(specifier) && specifier.text.startsWith('.')) {
        const dependency = resolve(root, dirname(path), specifier.text + (/\.(?:mjs|ts)$/.test(specifier.text) ? '' : '.ts'));
        queue.push(relative(root, dependency));
      }
      ts.forEachChild(node, visit);
    };
    visit(syntax);
  }
  const helpers = [...visited].filter(path => path.startsWith('.github/scripts/')).sort();
  assert.deepEqual(helpers, galleryHelperInputs.filter(path => path.startsWith('.github/scripts/')).sort());
  console.log(`Gallery closure: ${visited.size} versionable runtime/catalog/font files; ${helpers.length} reused tracked browser helpers.`);
});
}
