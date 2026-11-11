import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdir, open, readFile, realpath, stat, unlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const filename = fileURLToPath(import.meta.url);
const workspace = resolve(dirname(filename), '../..');
const helperNames = ['page-gallery.mjs', 'page-gallery-review.mjs', 'page-gallery-demo.mjs',
  'page-gallery-portal.mjs', 'page-gallery-account.mjs', 'page-gallery-admin.mjs', 'page-gallery-registration.mjs'];
export const galleryHelperInputs = [
  ...helperNames.map(name => `tools/page-gallery/${name}`),
  ...['acceptance-report.mjs', 'browser-localization.mjs', 'portal-harness.mjs',
    'portal-mail-sink.mjs', 'registration-browser.mjs', 'release-images.mjs',
    'smoke-image.mjs', 'web-portal.browser.mjs'].map(name => `.github/scripts/${name}`),
];
export const galleryLocales = ['en', 'fa-IR'];
export const galleryThemes = ['light', 'dark'];
export const galleryDevices = { desktop: { width: 1280, height: 900 }, mobile: { width: 390, height: 844 }, short: { width: 320, height: 256 } };
export const galleryRoutes = [
  ['home', '/', 'Hatef Identity Platform'], ['login', '/login', 'Sign in to Hatef'],
  ['passkey', '/login/webauthn', 'Sign in with a passkey'], ['register', '/register', 'Create your account'],
  ['verify-email', '/register/verify-email', 'Email verification unavailable'],
  ['forgot-password', '/forgot-password', 'Password reset unavailable'],
  ['reset-password', '/reset-password', 'Password reset unavailable'],
  ['verify-totp', '/verify-totp', 'Authenticator sign-in unavailable'],
  ['recover-account', '/recover-account', 'Recover your account'],
  ['dashboard', '/dashboard', 'Account overview'], ['profile', '/dashboard/profile', 'Profile'],
  ['security', '/dashboard/security', 'Security'], ['sessions', '/dashboard/sessions', 'Sessions'],
  ['privacy', '/dashboard/privacy', 'Privacy'], ['admin', '/admin', 'Admin control panel'],
  ['admin-users', '/admin/users', 'Accounts'], ['admin-user', '/admin/users/[id]', 'Account details'],
  ['admin-audit', '/admin/audit-logs', 'Audit logs'], ['admin-integrity', '/admin/integrity', 'Integrity verification'],
  ['admin-legal', '/admin/legal', 'DPO and Legal'],
];
const states = {
  home: ['display-settings'], passkey: ['app-cancelled'],
  register: ['native-input', 'email-pending', 'phone-ready', 'sms-code', 'sms-native-digits', 'passkey-ready', 'completed'],
  'verify-email': ['ready', 'confirmed'], 'recover-account': ['passkey-challenge', 'totp-entry', 'confirmed'],
  dashboard: ['navigation-closed', 'navigation-open'], profile: ['editing', 'conflict'],
  security: ['passkey-rename', 'step-up-totp', 'recovery-code-viewer'],
  sessions: ['remote-revoke-dialog'], privacy: ['deletion-enabled', 'deletion-dialog', 'deletion-confirmed'],
  admin: ['no-access', 'navigation-closed', 'navigation-open'],
  'admin-users': ['populated', 'table-view', 'empty', 'support-read-only', 'support-table-view'],
  'admin-user': ['moderation-entry', 'moderation-review', 'moderation-enabled'],
  'admin-audit': ['populated', 'table-view', 'audit-detail-dialog'],
  'admin-integrity': ['ledger-form', 'audit-report', 'ledger-report'],
  'admin-legal': ['holds-populated', 'holds-table-view', 'preservation-form', 'attribution-form',
    'hold-review', 'release-review', 'attribution-review', 'attribution-results', 'attribution-table-view'],
};
const headings = {
  'admin-no-access': 'Administration',
  'register-email-pending': 'Verify your email', 'register-phone-ready': 'Verify your mobile number',
  'register-sms-code': 'Verify your mobile number', 'register-sms-native-digits': 'Verify your mobile number',
  'register-passkey-ready': 'Create your passkey', 'register-completed': 'Account created',
  'verify-email-ready': 'Verify your email ownership', 'verify-email-confirmed': 'Email verified',
  'recover-account-confirmed': 'Account recovered', 'security-step-up-totp': 'Rename passkey',
  'security-recovery-code-viewer': 'Save your new recovery codes', 'sessions-remote-revoke-dialog': 'Revoke this session?',
  'privacy-deletion-dialog': 'Confirm account deletion', 'privacy-deletion-confirmed': 'Account deletion requested',
  'admin-user-moderation-entry': 'Suspend account', 'admin-user-moderation-review': 'Suspend account',
  'admin-user-moderation-enabled': 'Suspend account', 'admin-audit-audit-detail-dialog': 'Audit record details',
  'admin-legal-preservation-form': 'Record preservation', 'admin-legal-attribution-form': 'Attribution inquiry',
  'admin-legal-hold-review': 'Apply Legal Hold', 'admin-legal-release-review': 'Release Legal Hold request',
  'admin-legal-attribution-review': 'Attribution inquiry', 'admin-legal-attribution-results': 'Current attribution page',
  'admin-legal-attribution-table-view': 'Current attribution page',
};
const modal = new Set(['security-step-up-totp', 'sessions-remote-revoke-dialog', 'privacy-deletion-dialog',
  'admin-user-moderation-entry', 'admin-user-moderation-review', 'admin-user-moderation-enabled',
  'admin-audit-audit-detail-dialog', 'admin-legal-preservation-form', 'admin-legal-attribution-form',
  'admin-legal-hold-review', 'admin-legal-release-review', 'admin-legal-attribution-review']);
export const galleryViews = galleryRoutes.flatMap(([prefix, route, heading]) => ['baseline', ...(states[prefix] || [])].map(state => {
  const id = `${prefix}-${state}`;
  const mode = modal.has(id) ? 'viewport' : 'full-page';
  return { id, route, state, heading: headings[id] || heading,
    surface: prefix.startsWith('admin') ? 'admin' : route.startsWith('/dashboard') ? 'portal' : 'public',
    mode, devices: mode === 'viewport' && id.startsWith('admin-') ? ['desktop', 'mobile', 'short'] : ['desktop', 'mobile'],
    detail: modal.has(id) || /(?:populated|table-view|support-read-only|attribution-results)$/.test(id),
    navigation: state === 'navigation-open' ? 'open' : state === 'navigation-closed' ? 'closed' : null,
    resultView: state.includes('table-view') ? 'table' : null,
  };
})).concat({ id: 'not-found', route: '/[unknown]', state: 'not-found', heading: 'Page not found',
  surface: 'public', mode: 'full-page', devices: ['desktop', 'mobile'], detail: false, navigation: null, resultView: null });

export function galleryJobs(views = galleryViews) {
  assert.equal(new Set(views.map(view => view.id)).size, views.length, 'Duplicate declared gallery state');
  return views.flatMap(view => galleryLocales.flatMap(locale => view.devices.flatMap(device => galleryThemes.map(theme => {
    assert(/^[a-z][a-z0-9-]*$/.test(view.id) && galleryDevices[device], 'Unsafe declared gallery state');
    const viewport = galleryDevices[device];
    return { id: view.id, route: view.route, state: view.state, surface: view.surface, locale, device, viewport, theme,
      fixture: /^(?:\/admin|\/dashboard|\/register|\/recover-account)/.test(view.route) ? 'disposable' : 'public',
      mode: view.mode, status: 'pending', synthetic: true,
      path: `${locale}/${device}/${theme}/${view.id}-${locale}-${viewport.width}x${viewport.height}-${theme}.png` };
  }))));
}
export function galleryDetails(jobs = galleryJobs(), views = galleryViews) {
  return jobs.filter(job => views.find(view => view.id === job.id)?.detail).map(job => ({ ...job,
    id: `${job.id}-controls-detail`, parent: job.id, status: 'conditional', path: job.path.replace(job.id, `${job.id}-controls-detail`) }));
}
export function galleryProgress(manifest) {
  const locales = Object.fromEntries(galleryLocales.map(locale => {
    const jobs = manifest.jobs.filter(job => job.locale === locale);
    const ids = [...new Set(jobs.map(job => job.id))];
    return [locale, { expectedStates: ids.length,
      capturedStates: ids.filter(id => jobs.filter(job => job.id === id).every(job => job.status === 'captured')).length,
      completedStates: ids.filter(id => jobs.filter(job => job.id === id).every(job => job.status === 'captured' && job.decoded)).length,
      blockedStates: ids.filter(id => jobs.some(job => job.id === id && job.status === 'blocked')).length,
      failedStates: ids.filter(id => jobs.some(job => job.id === id && job.status === 'failed')).length,
      expectedCorePNGs: jobs.length, capturedCorePNGs: jobs.filter(job => job.status === 'captured').length,
      verifiedCorePNGs: jobs.filter(job => job.status === 'captured' && job.decoded).length,
      declaredDetailPNGs: manifest.details.filter(job => job.locale === locale).length,
      requiredDetailPNGs: manifest.details.filter(job => job.locale === locale && job.needed).length,
      capturedDetailPNGs: manifest.details.filter(job => job.locale === locale && job.status === 'captured' && job.decoded).length }];
  }));
  return { expectedStates: new Set(manifest.jobs.map(job => job.id)).size, expectedCorePNGs: manifest.jobs.length,
    declaredDetailPNGs: manifest.details.length,
    requiredDetailPNGs: manifest.details.filter(job => job.needed).length, locales };
}
export function validateGalleryManifest(manifest, { complete = false } = {}) {
  assert.equal(manifest.version, 2, 'Only newly declared galleries can be published');
  const expected = galleryJobs();
  const expectedDetails = galleryDetails(expected);
  const identity = job => [job.id, job.route, job.state, job.surface, job.locale, job.device, job.viewport,
    job.theme, job.mode, job.path, job.synthetic];
  assert.deepEqual(manifest.jobs.map(identity), expected.map(identity), 'Core gallery inventory changed');
  assert.deepEqual(manifest.details.map(identity), expectedDetails.map(identity), 'Detail gallery inventory changed');
  assert.equal(new Set([...manifest.jobs, ...manifest.details].map(job => job.path)).size, expected.length + expectedDetails.length);
  assert.equal(manifest.rendering, 'offline-sanitized-synthetic-clone');
  assert.equal(manifest.acceptancePrerequisite, 'parent-confirmed-browser-pass');
  assert(/^[0-9]+-[0-9]+$/.test(manifest.runId) && /^[0-9a-f]{40}$/.test(manifest.sourceSHA), 'Unsafe gallery provenance');
  const progress = galleryProgress(manifest);
  assert.equal(manifest.expectedViews, progress.expectedStates);
  assert.equal(manifest.expectedPNGs, progress.expectedCorePNGs);
  assert.deepEqual(manifest.progress, progress, 'Gallery progress does not match state inventory');
  for (const job of [...manifest.jobs, ...manifest.details]) {
    const keys = new Set(['id', 'route', 'state', 'surface', 'locale', 'device', 'viewport', 'theme', 'fixture',
      'mode', 'status', 'synthetic', 'path', 'parent', 'role', 'sourceAppearance', 'needed', 'width', 'height',
      'masked', 'demoValues', 'demoOverflow', 'fontVerified', 'decoded', 'issue']);
    assert(Object.keys(job).every(key => keys.has(key)), 'Unexpected private gallery job metadata');
    assert(['pending', 'captured', 'failed', 'blocked', 'conditional', 'not-needed'].includes(job.status));
    assert(!job.path.includes('..') && job.path.endsWith('.png'));
    if (job.status === 'captured') assert(job.masked === false && job.demoValues === true && job.synthetic === true &&
      ['app-preference', 'system-os'].includes(job.sourceAppearance), 'Captured source appearance was not observed honestly');
  }
  if (complete) {
    assert.equal(manifest.status, 'complete'); assert.equal(manifest.cleanup, 'completed');
    assert(manifest.jobs.every(job => job.status === 'captured' && job.decoded));
    assert(manifest.details.every(job => job.status === 'not-needed' || (job.status === 'captured' && job.decoded)));
    for (const detail of manifest.details) {
      const pair = manifest.details.filter(job => job.parent === detail.parent && job.device === detail.device && job.theme === detail.theme);
      assert.equal(pair.length, galleryLocales.length);
      assert(pair.every(job => job.status === detail.status && job.needed === (job.status === 'captured')), 'Incomplete paired detail');
    }
    assert.equal(manifest.capturedPNGs, expected.length); assert.equal(manifest.verifiedPNGs, expected.length);
    assert.equal(manifest.detailPNGs, manifest.details.filter(job => job.status === 'captured' && job.decoded).length);
  }
  return progress;
}
export const escapeGalleryHTML = value => String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
export function galleryHTML(manifest) {
  validateGalleryManifest(manifest);
  const escape = escapeGalleryHTML;
  const options = (id, values) => `<label>${escape(id)}<select id="${id}"><option value="all">All</option>${values.map(value => `<option value="${escape(value)}">${escape(value)}</option>`).join('')}</select></label>`;
  const cards = galleryViews.map(view => `<section data-surface="${view.surface}" data-view="${view.id}" data-state="${escape(view.state)}" data-route="${escape(view.route)}"><h2>${escape(view.route)} <small>${escape(view.state)}</small></h2>${view.devices.flatMap(device => galleryThemes.map(theme => `<div class="pair" data-device="${device}" data-theme="${theme}">${galleryLocales.map(locale => {
    const job = manifest.jobs.find(job => job.id === view.id && job.locale === locale && job.device === device && job.theme === theme);
    const detail = manifest.details.find(job => job.parent === view.id && job.locale === locale && job.device === device && job.theme === theme && job.status === 'captured');
    const image = row => `<a href="${escape(row.path)}"><img loading="lazy" src="${escape(row.path)}" alt="${escape(row.id)} ${locale} ${device} ${theme}"></a>`;
    return `<figure data-locale="${locale}"><figcaption>${locale} | ${device} | ${theme} | ${job.fixture} | ${job.mode} | synthetic clone</figcaption>${job.status === 'captured' ? image(job) : `<p class="blocked">${escape(job.status)}: ${escape(job.issue || 'pending')}</p>`}${detail ? `<details><summary>Synthetic controls detail</summary>${image(detail)}</details>` : ''}</figure>`;
  }).join('')}</div>`)).join('')}</section>`).join('');
  const controls = [options('surface', ['public', 'portal', 'admin']), options('route', [...new Set(galleryViews.map(view => view.route))]),
    options('state', [...new Set(galleryViews.map(view => view.state))]), options('view', galleryViews.map(view => view.id)),
    options('device', Object.keys(galleryDevices)), options('theme', galleryThemes), options('locale', galleryLocales)].join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'"><title>Bilingual synthetic page gallery</title><style>body{margin:0;background:#12151b;color:#edf0f6;font:16px system-ui}header{padding:24px;position:sticky;top:0;background:#1d2330;z-index:1}h1{margin:0 0 8px}select{margin:8px;padding:8px}section{padding:24px;border-bottom:1px solid #454c5b}.pair{display:grid;grid-template-columns:1fr 1fr;gap:16px}figure{margin:0;min-width:0}figcaption{padding:8px}img{width:100%;height:auto}a{color:#b7d6ff}[hidden]{display:none!important}@media(max-width:640px){.pair{grid-template-columns:1fr}header{position:static}}</style><header><h1>Bilingual Synthetic Page Gallery</h1><p>${manifest.capturedPNGs || 0}/${manifest.expectedPNGs} core PNGs; ${manifest.detailPNGs || 0} paired details; ${manifest.expectedViews} declared states per locale; ${escape(manifest.status)}; cleanup ${escape(manifest.cleanup)}</p><p>Source ${escape(manifest.sourceSHA)}. Sanitized offline presentation clones only. Synthetic values, timestamps and frozen controls cannot prove native inputs, first paint or transaction completion. Live appearance uses application preferences or System OS changes; any clone-only substitutions are synthetic. Parent browser acceptance is a prerequisite, not certified by this gallery.</p><a href="manifest.json">Coverage and progress manifest</a><nav>${controls}</nav></header>${cards}<script>for(const control of document.querySelectorAll('select'))control.addEventListener('change',()=>{for(const section of document.querySelectorAll('section[data-view]')){section.hidden=['surface','view','route','state'].some(key=>{const value=document.getElementById(key).value;return value!=='all'&&section.dataset[key]!==value});for(const pair of section.querySelectorAll('.pair')){pair.hidden=['device','theme'].some(key=>{const value=document.getElementById(key).value;return value!=='all'&&pair.dataset[key]!==value});for(const figure of pair.querySelectorAll('figure')){const value=document.getElementById('locale').value;figure.hidden=value!=='all'&&figure.dataset.locale!==value}}}})</script></html>`;
}
const usage = `Generate the complete uncovered bilingual page gallery.

Usage: node tools/page-gallery/generate-page-gallery.mjs [--check | --inventory | --help]
Workspace: npm exec -- nx run web:page-gallery
Check only: npm exec -- nx run web:check-page-gallery

Default: check prerequisites, build current web/API/fixture binaries through Nx,
capture every declared view in en/fa-IR at desktop/mobile and light/dark,
validate the PNGs and offline gallery, then update the latest-gallery link.

--check  Check prerequisites only; do not build, capture, or write artifacts.
--inventory  Print declared state/locale/core/detail counts without any capture.
--help   Show this help.

Requires Linux (or WSL2 Linux), Node 24+, npm 11+, installed workspace dependencies
and Playwright Chromium with system libraries, Go >= the checked-in module version,
OpenSSL 3+, and a running local Docker daemon with a Unix socket. Native Windows
and macOS are not supported. First-run image builds may need network
access. Debug logging is disabled for child processes, without changing your shell.

Output: test-output/page-gallery/<run-id>/
Latest: test-output/page-gallery/index.html
Sensitive fields show readable demo values, not live secrets. No gray covers.
Previous runs are preserved. This is illustration, not security/transaction evidence.
See docs/page-gallery.md for prerequisites, acceptance, resource costs and cleanup.
Generation requires PAGE_GALLERY_BROWSER_ACCEPTANCE=passed, set only after the
parent's formal browser acceptance passes. This explicit acknowledgement is not
independently verified by the synthetic gallery. Preparation does not grant
permission to generate or claim acceptance.
`;

export function galleryEnvironment(environment) {
  const env = { ...environment, NX_DAEMON: 'false', CI: 'true', NEXT_TELEMETRY_DISABLED: '1' };
  for (const key of ['DEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'PWDEBUG', 'NX_PROJECT_NAME']) delete env[key];
  return env;
}

// Await the actual capture process on interruption so its owned-fixture teardown
// finishes before releasing the generation lock. Never stream private errors.
function command(executable, args, { cwd, env, signal, capture = false, progress = false, timeout = 60 * 60_000 }) {
  signal.throwIfAborted();
  return new Promise((resolveCommand, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', line = '', failed = false, killTimer;
    const stop = () => {
      failed = true;
      const terminate = name => {
        if (!child.pid) return;
        try { process.platform === 'win32' ? child.kill(name) : process.kill(-child.pid, name); }
        catch (error) { if (error.code !== 'ESRCH') failed = true; }
      };
      terminate('SIGTERM');
      killTimer ??= setTimeout(() => terminate('SIGKILL'), 180_000);
    };
    const timer = setTimeout(stop, timeout);
    const cleanup = () => { clearTimeout(timer); clearTimeout(killTimer); signal.removeEventListener('abort', stop); };
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) stop();
    child.stdout.on('data', bytes => {
      if (capture) {
        output += bytes.toString('utf8');
        if (output.length > 64 * 1024) { output = ''; stop(); }
      }
      if (progress) {
        line += bytes.toString('utf8');
        const lines = line.split(/\r?\n/); line = lines.pop().slice(-4096);
        for (const value of lines) if (/^(?:en|fa-IR): [a-z][a-z0-9-]* \([0-9]{1,3}\/[0-9]{1,3}\) states [0-9]{1,3}\/[0-9]{1,3}$/.test(value)) console.log(value);
      }
    });
    child.stderr.resume();
    child.once('error', () => { cleanup(); reject(new Error('Required command unavailable.')); });
    child.once('close', code => {
      cleanup();
      if (failed || signal.aborted || code !== 0) reject(new Error('Generation command did not complete.'));
      else resolveCommand(output.trim());
    });
  });
}

export async function generateGallery({ root = workspace, environment = process.env, execute = command,
  checkOnly = false, log = console.log } = {}) {
  const env = galleryEnvironment(environment);
  const outputRoot = resolve(root, 'test-output/page-gallery');
  const runID = new Date().toISOString().replace(/\D/g, '') + '-' + process.pid;
  const output = resolve(outputRoot, runID);
  const lockPath = resolve(outputRoot, '.generation.lock');
  const controller = new AbortController();
  const interrupt = () => controller.abort(new Error('Generation interrupted.'));
  process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
  let lock, stage = 'prerequisites';
  const run = (executable, args, options = {}) => execute(executable, args,
    { cwd: root, env, signal: controller.signal, ...options });
  try {
    stage = 'Node runtime';
    assert(Number(process.versions.node.split('.')[0]) >= 24);
    stage = 'supported platform';
    assert.equal(process.platform, 'linux', 'Use Linux or WSL2 with native Linux tools');
    stage = 'OS temporary directory';
    await access(tmpdir(), constants.W_OK | constants.X_OK);
    stage = 'TLS runtime safety';
    assert.notEqual(env.NODE_TLS_REJECT_UNAUTHORIZED, '0');
    stage = 'diagnostic logging safety';
    assert(!process.env.NODE_DEBUG && !process.env.NODE_DEBUG_NATIVE);
    stage = 'profiling runtime safety';
    assert(!/(?:--inspect|--prof|--trace)/.test([env.NODE_OPTIONS, ...process.execArgv].join(' ')));
    stage = 'gallery helper inputs';
    for (const path of galleryHelperInputs) assert((await stat(resolve(root, path))).isFile());
    stage = 'Nx dependency inputs';
    assert((await stat(resolve(root, 'node_modules/nx/package.json'))).isFile());
    stage = 'npm runtime';
    assert(Number((await run('npm', ['--version'], { capture: true, timeout: 30_000 })).split('.')[0]) >= 11);
    stage = 'Git workspace';
    assert.equal(await realpath(await run('git', ['rev-parse', '--show-toplevel'], { capture: true, timeout: 30_000 })), await realpath(root));
    stage = 'Go runtime';
    const module = await readFile(resolve(root, 'apps/identity-api/go.mod'), 'utf8');
    const requiredGo = /^go (\d+)\.(\d+)\.(\d+)$/m.exec(module)?.slice(1).map(Number);
    const actualGo = /\bgo(\d+)\.(\d+)\.(\d+)\b/.exec(await run('go', ['version'], { capture: true, timeout: 30_000 }))?.slice(1).map(Number);
    assert(requiredGo && actualGo, 'Go module toolchain is required');
    const difference = actualGo.findIndex((value, index) => value !== requiredGo[index]);
    assert(difference === -1 || actualGo[difference] > requiredGo[difference], 'Go module toolchain is required');
    stage = 'OpenSSL runtime';
    assert(Number(/^OpenSSL (\d+)\./.exec(await run('openssl', ['version'], { capture: true, timeout: 30_000 }))?.[1]) >= 3);
    stage = 'local Docker endpoint';
    // Match Docker's selected endpoint, not a hard-coded socket or remote daemon.
    const endpoint = env.DOCKER_HOST && !env.DOCKER_CONTEXT ? { Host: env.DOCKER_HOST } :
      JSON.parse(await run('docker', ['context', 'inspect', '--format', '{{json .Endpoints.docker}}'], { capture: true, timeout: 30_000 }));
    assert(typeof endpoint.Host === 'string' && endpoint.Host.startsWith('unix://'), 'A local Docker Unix socket is required');
    stage = 'Docker daemon';
    await run('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 30_000 });
    stage = 'Playwright Chromium and system dependencies';
    await run(process.execPath, ['--input-type=module', '-e',
      "const {chromium}=await import('playwright');let browser;try{browser=await chromium.launch({headless:true});}finally{if(browser)await browser.close();}"], { timeout: 60_000 });
    log('Gallery prerequisites passed.');
    if (checkOnly) return;
    stage = 'formal browser acceptance prerequisite';
    assert.equal(env.PAGE_GALLERY_BROWSER_ACCEPTANCE, 'passed', 'Formal browser acceptance must pass before gallery generation');

    stage = 'generation lock';
    await mkdir(outputRoot, { recursive: true, mode: 0o700 });
    lock = await open(lockPath, 'wx', 0o600);
    await lock.writeFile(JSON.stringify({ pid: process.pid, runID }) + '\n');
    env.PAGE_GALLERY_RUN_ID = runID;
    env.PAGE_GALLERY_DEFER_LATEST = '1';

    stage = 'fresh web/API build'; log('[1/4] Building the current web and API (Nx cache bypassed)...');
    await run('npm', ['exec', '--', 'nx', 'run-many', '-t', 'build', '-p', 'web,identity-api', '--skipNxCache']);
    stage = 'fixture build'; log('[2/4] Building disposable gallery fixture services...');
    await run('npm', ['exec', '--', 'nx', 'run-many', '-t',
      'build-portal-fixture,build-deletion-notifier,build-audit-signer,build-admin-audit-publisher,build-admin-legal',
      '-p', 'identity-api', '--skipNxCache']);
    stage = 'page capture'; log('[3/4] Rendering every English/Persian view without covers...');
    // Direct Node ownership lets SIGTERM reach the generator's real cleanup,
    // rather than terminating an intermediate npm/Nx exec wrapper first.
    await run(process.execPath, [resolve(root, 'tools/page-gallery/page-gallery.mjs')], { progress: true });
    stage = 'gallery validation'; log('[4/4] Validating all images, cover checks, and offline filters...');
    await run(process.execPath, [resolve(root, 'tools/page-gallery/page-gallery-review.mjs'), runID]);
    const manifest = JSON.parse(await readFile(resolve(output, 'manifest.json'), 'utf8'));
    assert.equal(manifest.runId, runID);
    const progress = validateGalleryManifest(manifest, { complete: true });
    assert.equal(manifest.review.automated, 'passed'); assert.equal(manifest.review.grayCoverCheck, 'passed');
    assert.equal(manifest.review.offlineGallery, 'passed'); assert.equal(manifest.review.unexpectedNetwork, 0);
    assert.equal(manifest.review.privateArtifactInputs, 'readable-synthetic-demo-values-only');
    assert.equal(manifest.review.imageChecks, progress.expectedCorePNGs + manifest.detailPNGs);
    assert.deepEqual(manifest.review.progress, progress);
    stage = 'latest-gallery publication';
    controller.signal.throwIfAborted();
    await writeFile(resolve(outputRoot, 'index.html'), `<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=./${runID}/index.html"><title>Latest bilingual demo gallery</title><a href="./${runID}/index.html">Open the latest uncovered bilingual demo gallery</a></html>`, { mode: 0o600 });
    log(`Generated ${manifest.capturedPNGs} core images + ${manifest.detailPNGs} paired detail images.`);
    log(`Gallery: ${resolve(output, 'index.html')}`);
    log(`Latest: ${resolve(outputRoot, 'index.html')}`);
    return { runID, output, images: manifest.review.imageChecks };
  } catch (error) {
    const interrupted = controller.signal.aborted;
    const advice = stage === 'generation lock' && error.code === 'EEXIST'
      ? ' Another run or interrupted lock exists; remove .generation.lock only after confirming no generator is running.' : '';
    const failure = new Error(`${interrupted ? 'Interrupted' : 'Generation failed'} during ${stage}.${advice}`);
    failure.exitCode = interrupted ? 130 : 1;
    failure.output = output;
    throw failure;
  } finally {
    process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
    if (lock) {
      try {
        const owned = await lock.stat();
        const current = await stat(lockPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
        if (current?.ino === owned.ino && current.dev === owned.dev) await unlink(lockPath);
      } finally { await lock.close(); }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === filename) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') console.log(usage);
  else if (args.length === 1 && args[0] === '--inventory') console.log(JSON.stringify(galleryProgress({ jobs: galleryJobs(), details: galleryDetails() }), null, 2));
  else if (args.length === 0 || (args.length === 1 && args[0] === '--check')) {
    await generateGallery({ checkOnly: args[0] === '--check' }).catch(error => {
      console.error(error.message);
      if (error.output) console.error(`Run output (if capture started): ${error.output}`);
      process.exitCode = error.exitCode || 1;
    });
  } else { console.error(usage); process.exitCode = 1; }
}
