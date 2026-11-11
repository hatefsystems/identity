import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { browserLocales, setBrowserLocale, setBrowserTheme, assertBrowserTheme, localizedText, waitForFonts, screenshotName } from '../../.github/scripts/browser-localization.mjs';
import { createDemoRenderer } from './page-gallery-demo.mjs';
import { galleryRoutes as routes, galleryViews as views, galleryDevices as devices, galleryThemes as themes,
  galleryJobs, galleryDetails, galleryProgress, galleryHTML, validateGalleryManifest } from './generate-page-gallery.mjs';

if (process.env.NX_PROJECT_NAME && process.env.NX_PROJECT_NAME !== 'web') process.exit(0);
process.chdir(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
export { views };
if (!process.argv.includes('--validate-only')) assert.equal(process.env.PAGE_GALLERY_BROWSER_ACCEPTANCE, 'passed', 'Parent formal browser acceptance is required');
const runId = process.env.PAGE_GALLERY_RUN_ID || new Date().toISOString().replace(/\D/g, '') + '-' + process.pid;
assert(/^[0-9]+-[0-9]+$/.test(runId));
const output = resolve('test-output/page-gallery', runId);
const sourceSHA = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
assert(/^[0-9a-f]{40}$/.test(sourceSHA));
const appPaths = JSON.parse(await readFile(resolve('apps/web/.next/server/app-paths-manifest.json'), 'utf8'));
const builtRoutes = Object.keys(appPaths).filter(path => path.endsWith('/page') && !/^\/_/.test(path))
  .map(path => path.replace(/\/\([^/]+\)/g, '').replace(/\/page$/, '') || '/').sort();
assert.deepEqual(builtRoutes, routes.map(([, path]) => path).sort(), 'Required route coverage changed');
const manifest = {
  version: 2, runId, sourceSHA, expectedViews: views.length, expectedPNGs: galleryJobs().length,
  status: 'incomplete', rendering: 'offline-sanitized-synthetic-clone', acceptancePrerequisite: 'parent-confirmed-browser-pass',
  evidence: 'Offline sanitized synthetic clones only. Real source themes use UI preferences or System OS changes. Values, timestamps and frozen clone controls are illustrative, not native-input/first-paint/transaction proof.',
  excluded: ['native-authenticator-prompts', 'screen-readers', 'native-zoom', 'deployed-ingress', 'professional-persian-wording-review', 'forced-error-boundaries'],
  replacements: ['disconnected-auth-forms-to-availability-notices', 'registration-phase-headings-and-native-digits',
    'compact-navigation-explicit-destinations', 'compact-results-optional-table', 'short-height-native-review-control-states',
    'recovery-count-first-viewer', 'explicit-conflict-refresh', 'integrity-start-and-results', 'shared-brand-home-auth-404'],
  cleanup: 'pending', findings: [], jobs: galleryJobs(), details: galleryDetails(),
};
manifest.progress = galleryProgress(manifest);
validateGalleryManifest(manifest);
if (process.argv.includes('--validate-only')) {
  assert.throws(() => screenshotName('../unsafe', devices.desktop, false));
  assert.throws(() => setBrowserLocale('unsupported'));
  console.log(JSON.stringify({ routes: routes.length, ...manifest.progress }));
  process.exit(0);
}
await mkdir(dirname(output), { recursive: true, mode: 0o700 });
await mkdir(output, { mode: 0o700 });
async function save() {
  manifest.progress = galleryProgress(manifest);
  await writeFile(resolve(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
}
await save();
const contexts = new Set(), cleanups = [], detailBuffers = new Map(), signInTimes = [];
let renderer, interrupted = false;
const abort = new AbortController();
const api = {
  output, views, contexts, cleanups,
  async beforeSignIn() {
    while (signInTimes.length && Date.now() - signInTimes[0] >= 61_000) signInTimes.shift();
    if (signInTimes.length >= 4) {
      console.log('Respecting the real passkey admission window before fresh sign-in.');
      await delay(Math.max(1, signInTimes[0] + 61_000 - Date.now()), undefined, { signal: abort.signal });
      while (signInTimes.length && Date.now() - signInTimes[0] >= 61_000) signInTimes.shift();
    }
    signInTimes.push(Date.now());
  },
  finding(category, surface = 'public') {
    assert(['service-log-privacy-guard', 'horizontal-overflow', 'nested-scroller-controls'].includes(category));
    assert(['public', 'portal', 'admin', 'registration'].includes(surface));
    manifest.findings.push({ locale: api.locale, surface, category });
  },
  async group(ids, operation) {
    assert(ids.every(id => views.some(view => view.id === id)), 'Undeclared gallery group');
    try { if (interrupted) throw new Error('Interrupted'); await operation(); }
    catch (error) {
      const category = interrupted ? 'run-interrupted' : error?.name === 'TimeoutError' ? 'state-readiness-timeout' : 'fixture-or-state-unavailable';
      for (const job of manifest.jobs) if (job.locale === api.locale && ids.includes(job.id) && job.status === 'pending') {
        job.status = 'blocked'; job.issue = category;
      }
      console.log(`Blocked ${ids.join(', ')}: ${category}`);
      const location = /(?:^|\n)\s*at[^\n]*[\/](page-gallery-[a-z-]+\.mjs):(\d+):(\d+)/.exec(typeof error?.stack === 'string' ? error.stack : '');
      if (location) console.log(JSON.stringify({ galleryFailure: category, helper: location[1], line: Number(location[2]) }));
      await save();
    }
  },
  async capture(page, id, { heading, modal = false, sensitiveSelectors = [], sensitive = false, role = 'demo', prepare } = {}) {
    const view = views.find(view => view.id === id);
    assert(view && /^[a-z][a-z0-9-]*$/.test(id), 'Undeclared capture');
    assert(['demo', 'anonymous', 'ordinary', 'combined', 'support'].includes(role));
    assert(Array.isArray(sensitiveSelectors) && sensitiveSelectors.every(selector => typeof selector === 'string' && selector.length));
    const privateState = /^\/(?:admin|dashboard)(?:\/|$)/.test(view.route) ||
      (['/register', '/register/verify-email', '/recover-account'].includes(view.route) && view.state !== 'baseline');
    assert(!(sensitive || privateState) || (sensitive && sensitiveSelectors.length), 'Sensitive state has no reviewed demo-value rendering');
    assert(!heading || heading === view.heading, 'Capture heading differs from declared current task');
    assert.equal(view.mode, modal ? 'viewport' : 'full-page');
    await page.bringToFront();
    page.setDefaultTimeout(12000);
    const expected = localizedText(view.heading);
    await page.getByRole('heading', { name: expected, exact: true }).first().waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'), api.locale);
    assert.equal(await page.locator('html').getAttribute('dir'), api.locale === 'fa-IR' ? 'rtl' : 'ltr');
    const marker = await page.evaluate(() => document.__galleryDocument ||= crypto.randomUUID());
    for (const device of view.devices) for (const theme of themes) {
      const viewport = devices[device];
      const job = manifest.jobs.find(job => job.id === id && job.locale === api.locale && job.device === device && job.theme === theme);
      assert.equal(job.status, 'pending', 'Duplicate capture attempt');
      job.role = role;
      let stage = 'state-readiness';
      try {
        if (interrupted) throw new Error('Interrupted');
        // Only explicitly unsent reviews may supply fresh fixture verification;
        // no clock is frozen and no sent operation is replayed for a picture.
        if (prepare) await prepare({ page, device, viewport, theme });
        await page.setViewportSize(viewport);
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
        if (modal) {
          assert.equal(await page.locator('html').getAttribute('data-theme'), 'system');
          await assertBrowserTheme(page, 'system');
          job.sourceAppearance = 'system-os';
        } else {
          await setBrowserTheme(page, theme);
          job.sourceAppearance = 'app-preference';
        }
        const navigation = page.locator('[data-portal-navigation-toggle]');
        if (view.navigation && await navigation.isVisible()) {
          if (await navigation.getAttribute('aria-expanded') !== String(view.navigation === 'open')) await navigation.click();
          assert.equal(await navigation.getAttribute('aria-expanded'), String(view.navigation === 'open'));
        }
        if (view.navigation) {
          const destinations = view.surface === 'admin' ? ['/admin', '/admin/users', '/admin/audit-logs', '/admin/integrity', '/admin/legal']
            : ['/dashboard', '/dashboard/profile', '/dashboard/security', '/dashboard/sessions', '/dashboard/privacy'];
          assert.deepEqual(await page.locator('[data-portal-navigation-links] a').evaluateAll(nodes => nodes.map(node => node.getAttribute('href'))), destinations);
        }
        const results = page.locator('[data-result-view]');
        if (!modal && await results.count() && viewport.width < 1024) {
          await page.getByRole('button', { name: localizedText(view.resultView === 'table' ? 'Table view' : 'Compact rows'), exact: true }).click();
          assert.equal(await results.getAttribute('data-result-view'), view.resultView || 'compact');
        }
        await page.evaluate(() => {
          window.scrollTo(0, 0);
          for (const node of document.querySelectorAll('*')) if (node.scrollTop || node.scrollLeft) { node.scrollTop = 0; node.scrollLeft = 0; }
        });
        await waitForFonts(page);
        stage = 'theme-validation';
        assert.equal(await page.evaluate(() => document.documentElement.classList.contains('dark')), theme === 'dark');
        assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), theme === 'dark' ? 'rgb(2, 8, 23)' : 'rgb(255, 255, 255)');
        assert.equal(await page.evaluate(() => document.__galleryDocument), marker, 'Capture replaced private document');
        await page.getByRole('heading', { name: expected, exact: true }).first().waitFor();
        if (modal) assert(await page.locator('dialog[open], [role="dialog"]').count(), 'Modal expired or closed');
        stage = 'font-validation';
        const font = await page.evaluate(() => ({ family: getComputedStyle(document.body).fontFamily,
          local: performance.getEntriesByType('resource').filter(entry => /\.woff2(?:\?|$)/.test(entry.name)).every(entry => new URL(entry.name).origin === location.origin),
          loaded: [...document.fonts].some(font => font.status === 'loaded' && font.family === 'persianFont') }));
        assert(font.local);
        if (api.locale === 'fa-IR') assert(font.loaded && /^persianFont(?:,|$)/.test(font.family));
        if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) manifest.findings.push({ id, locale: api.locale, device, theme, category: 'horizontal-overflow' });
        const filename = screenshotName(id, viewport, theme === 'dark');
        assert(job.path.endsWith(filename));
        stage = 'demo-png-capture';
        await mkdir(resolve(output, api.locale, device, theme), { recursive: true });
        const options = { selectors: ['input', 'textarea', 'pre', 'code', '[data-private]', ...sensitiveSelectors],
          privateValues: api.privateValues(), locale: api.locale, fullPage: !modal, viewport, theme };
        const png = await renderer.capture(page, options);
        assert(png.length > 100 && png.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
        assert(png.readUInt32BE(16) >= viewport.width);
        if (modal) { assert.equal(png.readUInt32BE(16), viewport.width); assert.equal(png.readUInt32BE(20), viewport.height); }
        else if (png.readUInt32BE(16) > viewport.width) {
          job.demoOverflow = true; manifest.findings.push({ id, locale: api.locale, device, theme, category: 'demo-horizontal-overflow' });
        }
        await writeFile(resolve(output, job.path), png, { mode: 0o600 });
        Object.assign(job, { width: png.readUInt32BE(16), height: png.readUInt32BE(20), status: 'captured', masked: false, demoValues: true, fontVerified: true });
        if (view.detail) {
          const detail = manifest.details.find(job => job.parent === id && job.locale === api.locale && job.device === device && job.theme === theme);
          detail.needed = await page.evaluate(modal => {
            const region = modal ? document.querySelector('dialog[open], [role="dialog"]') : document.querySelector('main');
            if (!region) return false;
            const scrollers = [region, ...region.querySelectorAll('*')].filter(node => {
              const style = getComputedStyle(node);
              return (node.scrollHeight > node.clientHeight + 1 && /auto|scroll/.test(style.overflowY)) || (node.scrollWidth > node.clientWidth + 1 && /auto|scroll/.test(style.overflowX));
            });
            const hidden = scrollers.some(node => {
              const rect = node.getBoundingClientRect();
              return [...node.querySelectorAll('button, a[href], input, select, textarea')].some(control => {
                const box = control.getBoundingClientRect();
                return box.width && box.height && !control.closest('[hidden]') &&
                  ((node.scrollHeight > node.clientHeight + 1 && (box.bottom > rect.bottom + 1 || box.top < rect.top - 1)) ||
                    (node.scrollWidth > node.clientWidth + 1 && (box.right > rect.right + 1 || box.left < rect.left - 1)));
              });
            });
            for (const node of scrollers) { node.scrollTop = node.scrollHeight; node.scrollLeft = getComputedStyle(node).direction === 'rtl' ? -node.scrollWidth : node.scrollWidth; }
            return hidden;
          }, modal);
          await waitForFonts(page);
          detailBuffers.set(detail.path, await renderer.capture(page, options));
          Object.assign(detail, { role, masked: false, demoValues: true, sourceAppearance: job.sourceAppearance });
        }
      } catch (error) { job.status = 'failed'; job.issue = error?.name === 'TimeoutError' ? 'state-readiness-timeout' : `${stage}-failed`; }
      await save();
    }
    const jobs = manifest.jobs.filter(job => job.id === id && job.locale === api.locale);
    const progress = galleryProgress(manifest).locales[api.locale];
    console.log(`${api.locale}: ${id} (${jobs.filter(job => job.status === 'captured').length}/${jobs.length}) states ${progress.capturedStates}/${progress.expectedStates}`);
    if (interrupted) throw new Error('Interrupted');
  },
};
async function cleanup() {
  let ok = true;
  for (const context of contexts) await context.close().catch(() => { ok = false; });
  for (const close of cleanups.reverse()) await close().catch(() => { ok = false; });
  manifest.cleanup = ok ? 'completed' : 'failed';
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { interrupted = true; abort.abort(); });
try {
  renderer = await createDemoRenderer(); cleanups.push(() => renderer.close());
  const { portalPhase } = await import('./page-gallery-portal.mjs');
  for (const locale of browserLocales) {
    api.locale = locale; setBrowserLocale(locale);
    await api.group(views.filter(view => !view.id.startsWith('register-') && !view.id.startsWith('verify-email-')).map(view => view.id), () => portalPhase(api));
  }
  const { registrationPhase } = await import('./page-gallery-registration.mjs');
  for (const locale of browserLocales) {
    api.locale = locale; setBrowserLocale(locale);
    await api.group(views.filter(view => view.id.startsWith('register-') || view.id.startsWith('verify-email-')).map(view => view.id), () => registrationPhase(api));
  }
} catch { for (const job of manifest.jobs) if (job.status === 'pending') { job.status = 'blocked'; job.issue = 'runner-prerequisite-unavailable'; } }
finally {
  await cleanup();
  for (const job of manifest.jobs) if (job.status === 'pending') { job.status = 'blocked'; job.issue = 'required-state-not-captured'; }
  for (const view of views.filter(view => view.detail)) for (const device of view.devices) for (const theme of themes) {
    const pair = manifest.details.filter(job => job.parent === view.id && job.device === device && job.theme === theme);
    const needed = pair.some(job => job.needed);
    for (const detail of pair) {
      detail.needed = needed;
      const data = detailBuffers.get(detail.path);
      if (!needed) { detail.status = 'not-needed'; continue; }
      if (!data) { detail.status = 'blocked'; detail.issue = 'paired-detail-unavailable'; continue; }
      await writeFile(resolve(output, detail.path), data, { mode: 0o600 });
      Object.assign(detail, { status: 'captured', width: data.readUInt32BE(16), height: data.readUInt32BE(20) });
      manifest.findings.push({ id: detail.parent, locale: detail.locale, device, theme, category: 'nested-scroller-controls', detail: detail.path });
    }
  }
  detailBuffers.clear();
  const decoder = interrupted ? null : await chromium.launch({ headless: true }).catch(() => null);
  if (decoder) try {
    const page = await decoder.newPage();
    for (const job of [...manifest.jobs, ...manifest.details].filter(job => job.status === 'captured')) try {
      assert((await stat(resolve(output, job.path))).size > 100);
      const data = await readFile(resolve(output, job.path));
      const dimensions = await page.evaluate(async base64 => {
        const image = await createImageBitmap(await (await fetch('data:image/png;base64,' + base64)).blob());
        const dimensions = [image.width, image.height]; image.close(); return dimensions;
      }, data.toString('base64'));
      assert.deepEqual(dimensions, [job.width, job.height]); job.decoded = true;
    } catch { job.status = 'failed'; job.issue = 'png-decode-failed'; }
  } finally { await decoder.close(); }
  for (const view of views) for (const device of view.devices) for (const theme of themes) {
    const pair = manifest.jobs.filter(job => job.id === view.id && job.device === device && job.theme === theme);
    assert.equal(pair.length, browserLocales.length); assert.deepEqual(pair.map(job => job.locale).sort(), [...browserLocales].sort());
  }
  manifest.capturedPNGs = manifest.jobs.filter(job => job.status === 'captured').length;
  manifest.verifiedPNGs = manifest.jobs.filter(job => job.status === 'captured' && job.decoded).length;
  manifest.blockedPNGs = manifest.jobs.filter(job => job.status === 'blocked').length;
  manifest.failedPNGs = manifest.jobs.filter(job => job.status === 'failed').length;
  manifest.interrupted = interrupted;
  manifest.detailPNGs = manifest.details.filter(job => job.status === 'captured' && job.decoded).length;
  manifest.status = manifest.verifiedPNGs === manifest.expectedPNGs && manifest.cleanup === 'completed' &&
    manifest.details.every(job => job.status === 'not-needed' || (job.status === 'captured' && job.decoded)) ? 'complete' : 'incomplete';
  await save();
  await writeFile(resolve(output, 'index.html'), galleryHTML(manifest), { mode: 0o600 });
  // Only the launcher publishes latest, after independent image/offline review.
  console.log(`Gallery: ${output}/index.html; ${manifest.capturedPNGs}/${manifest.expectedPNGs} core PNGs; ${manifest.detailPNGs} paired details; ${manifest.status}; cleanup ${manifest.cleanup}`);
  if (manifest.status !== 'complete') process.exitCode = 1;
}
