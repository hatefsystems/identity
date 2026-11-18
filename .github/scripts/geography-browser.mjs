import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { acceptanceIdentity, assertGeographyReport, assertIdentity, geographyChecks, geographyJourneys, geographyLocaleChecks, geographyLocales } from './acceptance-report.mjs';
import { browserFailure, guardBrowserFailures, portalCleanup } from './portal-harness.mjs';
import { geographyReadRoute, startGeographyHarness } from './geography-harness.mjs';
import { geographyFixtureMarker, geographyFixtureRoute } from './geography-fixture.mjs';
import { trustRegistrationFixtureCA } from './registration-browser.mjs';

export const geographyNames = Object.freeze({
  en: Object.freeze({ province: 'Province (required)', locality: 'City, urban area, or village (optional)',
    clearProvince: 'Clear province', clearLocality: 'Clear city, urban area, or village', skip: 'Skip city, urban area, or village',
    more: 'Load more results', retry: 'Retry', close: 'Close picker',
    empty: 'No matching locations. Try a different name.', unavailable: 'Locations are temporarily unavailable. Retry when you are ready.',
    catalogChanged: 'The location catalog changed. Retry to browse the current catalog.', rateLimited: 'Too many location requests. Wait before retrying.' }),
  'fa-IR': Object.freeze({ province: 'استان (الزامی)', locality: 'شهر، منطقه شهری یا روستا (اختیاری)',
    clearProvince: 'پاک کردن استان', clearLocality: 'پاک کردن شهر، منطقه شهری یا روستا', skip: 'رد شدن از انتخاب شهر، منطقه شهری یا روستا',
    more: 'نمایش نتایج بیشتر', retry: 'تلاش دوباره', close: 'بستن انتخاب‌گر',
    empty: 'مکانی مطابق جست‌وجو یافت نشد. نام دیگری را امتحان کنید.', unavailable: 'مکان‌ها موقتاً در دسترس نیستند. هر زمان آماده بودید دوباره تلاش کنید.',
    catalogChanged: 'فهرست مکان‌ها تغییر کرده است. برای مرور فهرست فعلی دوباره تلاش کنید.', rateLimited: 'درخواست‌های مکان بیش از حد مجاز است. پیش از تلاش دوباره صبر کنید.' }),
});

export function geographyBounds() {
  const failures = [];
  if (document.documentElement.scrollWidth > innerWidth + 1) failures.push('horizontal-overflow');
  const dialog = document.querySelector('dialog[open]');
  if (dialog) {
    const box = dialog.getBoundingClientRect();
    if (box.left < -1 || box.right > innerWidth + 1 || box.top < -1 || box.bottom > innerHeight + 1) failures.push('dialog-outside-viewport');
    if (!dialog.contains(document.activeElement)) failures.push('dialog-focus-escaped');
  }
  for (const element of (dialog ?? document).querySelectorAll('button,input,[role=option]')) {
    if (!element.checkVisibility() || element.matches(':disabled')) continue;
    const box = element.getBoundingClientRect();
    if (box.width < 44 || box.height < 44) failures.push('touch-target-below-44');
    if (box.left < -1 || box.right > innerWidth + 1) failures.push('control-horizontal-overflow');
  }
  const active = document.activeElement;
  if (active?.matches('input,button')) {
    const style = getComputedStyle(active);
    const outline = parseFloat(style.outlineWidth) >= 2 && !['none', 'hidden'].includes(style.outlineStyle);
    if (active.matches(':focus-visible') && !outline && style.boxShadow === 'none') failures.push('missing-visible-focus');
  }
  return [...new Set(failures)];
}

export function expectedGeographyResourceFailure(message, origin, responses) {
  try {
    const location = message.location().url;
    const url = new URL(location);
    const status = responses.get(location);
    const reason = { 400: 'Bad Request', 409: 'Conflict', 429: 'Too Many Requests', 503: 'Service Unavailable', 404: 'Not Found' }[status];
    const owned = url.origin === origin && !url.hash && (status === 404
      ? url.pathname === '/favicon.ico' && !url.search
      : geographyReadRoute('GET', url.pathname + url.search));
    if (!owned || !reason || message.type() !== 'error' ||
      message.text() !== `Failed to load resource: the server responded with a status of ${status} (${reason})`) return false;
    responses.delete(location);
    return true;
  } catch { return false; }
}

async function settled(page) {
  await page.evaluate(async () => { await document.fonts.ready;
    await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))); });
}

async function selection(page, expected) {
  await page.waitForFunction((value) => document.querySelector('[data-testid=selection]')?.textContent === JSON.stringify(value), expected);
}

async function currentSelection(page) {
  return JSON.parse(await page.getByTestId('selection').textContent());
}

export function geographySelectedMetadataReady() {
  // A committed ID renders an LTR bdi before the separate lookup completes.
  // Wait for original display labels/type/ancestry, not that ID placeholder.
  return document.querySelector('[data-location-selected=locality]')?.querySelectorAll('bdi[dir="auto"]').length >= 4 &&
    document.querySelector('[data-location-selected=province]')?.querySelectorAll('bdi[dir="auto"]').length >= 2;
}

async function openPicker(page, locale, field, mobile) {
  const section = page.locator(`[data-location-field=${field}]`);
  if (mobile) await section.getByRole('button', { name: geographyNames[locale][field], exact: true }).click();
  const scope = mobile ? page.getByTestId(`location-${field}-dialog`) : section;
  if (mobile) await scope.waitFor({ state: 'visible' });
  const input = scope.getByRole('combobox', { name: geographyNames[locale][field], exact: true });
  await input.click();
  await scope.getByRole('option').first().waitFor({ state: 'visible' });
  return { scope, input };
}

async function choose(page, locale, field, id, mobile = false) {
  const { scope } = await openPicker(page, locale, field, mobile);
  await scope.locator(`[role=option][id$="-option-${id}"]`).click();
}

async function screenshot(page, directory, locale, journey) {
  await settled(page);
  assert.deepEqual(await page.evaluate(geographyBounds), []);
  if (directory) await page.screenshot({ path: resolve(directory, `${locale}-${journey}.png`), animations: 'disabled',
    mask: [page.locator('input,bdi,[role=status],[data-location-selected],[data-geography-private]')], maskColor: '#64748b' });
}

export async function validateGeographyBrowser(harness, locale, directory) {
  assert(geographyLocales.includes(locale));
  const resources = [], close = portalCleanup(resources), names = geographyNames[locale], checks = new Set(), journeys = [];
  const failures = new Set();
  let context;
  try {
    resources.push(trustRegistrationFixtureCA(harness.tlsCA, harness.tlsCAPath));
    const browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`] });
    resources.push(() => browser.close());
    context = await browser.newContext({ viewport: { width: 1280, height: 800 }, serviceWorkers: 'block', colorScheme: 'light' });
    resources.push(() => context.close());
    context.setDefaultTimeout(15_000);
    const resourceFailures = new Map();
    context.on('response', (response) => {
      const status = response.status();
      if ([400, 404, 409, 429, 503].includes(status)) {
        if (resourceFailures.size >= 32) failures.add('resource-observation-overflow');
        else resourceFailures.set(response.url(), status);
      }
    });
    context.on('console', (message) => {
      if (!expectedGeographyResourceFailure(message, harness.origin, resourceFailures)) failures.add('browser-console');
    });
    context.on('pageerror', () => failures.add('browser-pageerror'));
    context.on('request', (request) => {
      try {
        const url = new URL(request.url());
        if (url.origin !== harness.origin) failures.add('cross-origin-request');
        if (url.pathname.startsWith('/api/') && !geographyReadRoute(request.method(), url.pathname + url.search)) failures.add('unexpected-api-work');
      } catch { failures.add('invalid-browser-request'); }
    });
    const page = await context.newPage();
    await page.goto(harness.origin + geographyFixtureRoute);
    await page.getByTestId(geographyFixtureMarker).waitFor({ state: 'visible' });
    await page.getByTestId(`locale-${locale}`).click();
    assert.equal(await page.locator('html').getAttribute('lang'), locale);
    assert.equal(await page.locator('html').getAttribute('dir'), locale === 'fa-IR' ? 'rtl' : 'ltr');
    assert.equal(await page.locator('[data-location-field=locality]').getByRole('combobox', { name: names.locality, exact: true }).isDisabled(), true);
    await selection(page, null);
    checks.add('required-province-optional-locality');
    const { input: provinceInput, scope: provinceScope } = await openPicker(page, locale, 'province', false);
    await provinceInput.fill('Alpha');
    await provinceScope.locator('[role=option][id$="-option-1"]').waitFor({ state: 'visible' });
    await provinceInput.press('Enter'); await selection(page, null);
    checks.add('draft-never-selects');
    await provinceInput.press('ArrowDown');
    assert.match(await provinceInput.getAttribute('aria-activedescendant'), /-option-1$/);
    assert.deepEqual(await page.evaluate(geographyBounds), []);
    await provinceInput.press('Enter'); await selection(page, { country: 'IR', province_id: '1' });
    const { input: localityInput, scope: localityScope } = await openPicker(page, locale, 'locality', false);
    await localityInput.fill('کیان آباد');
    await localityScope.locator('[role=option][id$="-option-13"]').waitFor({ state: 'visible' });
    assert.equal(await localityScope.getByRole('option').count(), 1);
    await localityInput.fill('Literal %_\\');
    await localityScope.locator('[role=option][id$="-option-14"]').waitFor({ state: 'visible' });
    assert.equal(await localityScope.getByRole('option').count(), 1);
    await localityInput.fill('NoSuchSyntheticPrefix');
    await localityScope.getByText(names.empty, { exact: true }).waitFor({ state: 'visible' });
    assert.equal(await localityScope.getByRole('option').count(), 0);
    checks.add('normalized-prefix-literal-search');
    await localityInput.fill('Alpha nested');
    await localityScope.locator('[role=option][id$="-option-12"]').waitFor({ state: 'visible' });
    await localityInput.press('ArrowDown'); await localityInput.press('Enter');
    await selection(page, { country: 'IR', province_id: '1', locality_id: '12' });
    await page.waitForFunction(geographySelectedMetadataReady);
    assert(await page.locator('[data-location-selected=locality] bdi').count() >= 4, 'Missing original type/ancestor metadata');
    await page.getByRole('button', { name: names.clearLocality, exact: true }).click();
    await selection(page, { country: 'IR', province_id: '1' });
    await choose(page, locale, 'locality', '11');
    await page.getByRole('button', { name: names.skip, exact: true }).click();
    await selection(page, { country: 'IR', province_id: '1' });
    await choose(page, locale, 'locality', '11');
    await choose(page, locale, 'province', '2');
    await selection(page, { country: 'IR', province_id: '2' });
    await choose(page, locale, 'locality', '20');
    await page.getByRole('button', { name: names.clearProvince, exact: true }).click(); await selection(page, null);
    checks.add('clear-skip-province-change');
    await choose(page, locale, 'province', '1');
    const delayed = harness.arm('/api/v1/geography/localities', 'delay');
    // Open without waiting for options: the genuine first response is held at
    // the owned ingress, while the next search supersedes that request.
    const localField = page.locator('[data-location-field=locality]');
    const staleInput = localField.getByRole('combobox', { name: names.locality, exact: true });
    await staleInput.focus(); await delayed.arrived;
    await staleInput.fill('Literal %_\\');
    await localField.locator('[role=option][id$="-option-14"]').waitFor({ state: 'visible' });
    delayed.release(); await settled(page);
    assert.equal(await localField.getByRole('option').count(), 1);
    await selection(page, { country: 'IR', province_id: '1' });
    await staleInput.press('Escape');
    assert.equal(await staleInput.getAttribute('aria-expanded'), 'false');
    checks.add('keyboard-selection-escape');
    const previousProvince = harness.arm('/api/v1/geography/localities', 'delay');
    await staleInput.fill('Alpha'); await previousProvince.arrived;
    await choose(page, locale, 'province', '2');
    const newProvince = await openPicker(page, locale, 'locality', false);
    await newProvince.scope.locator('[role=option][id$="-option-20"]').waitFor({ state: 'visible' });
    previousProvince.release(); await settled(page);
    assert.equal(await newProvince.scope.getByRole('option').count(), 1);
    assert.equal(await newProvince.scope.locator('[role=option][id$="-option-11"]').count(), 0);
    await selection(page, { country: 'IR', province_id: '2' });
    await newProvince.input.press('Escape');
    await choose(page, locale, 'province', '1');
    checks.add('stale-response-rejected');
    for (const [kind, statusName] of [['unavailable', names.unavailable], ['rate-limited', names.rateLimited]]) {
      harness.arm('/api/v1/geography/localities', kind);
      await staleInput.fill('Page');
      await localField.getByText(statusName, { exact: true }).waitFor({ state: 'visible' });
      assert.equal(await localField.getByRole('option').count(), 0);
      await localField.getByRole('button', { name: names.retry, exact: true }).click();
      await localField.locator('[role=option][id$="-option-100"]').waitFor({ state: 'visible' });
      await staleInput.press('Escape');
    }
    checks.add('unavailable-retry');
    const paging = await openPicker(page, locale, 'locality', false);
    await paging.input.fill('Page');
    await paging.scope.locator('[role=option][id$="-option-100"]').waitFor({ state: 'visible' });
    assert.equal(await paging.scope.getByRole('option').count(), 20);
    await paging.scope.getByRole('button', { name: names.more, exact: true }).click();
    await paging.scope.locator('[role=option][id$="-option-123"]').waitFor({ state: 'visible' });
    assert.equal(await paging.scope.getByRole('option').count(), 24);
    assert.equal(await paging.scope.getByRole('button', { name: names.more, exact: true }).count(), 0);
    checks.add('explicit-bounded-pagination');
    await paging.input.fill('Page 0');
    await paging.scope.locator('[role=option][id$="-option-100"]').waitFor({ state: 'visible' });
    await paging.input.fill('Page');
    await paging.scope.getByRole('button', { name: names.more, exact: true }).waitFor({ state: 'visible' });
    await harness.importSnapshot(true);
    await paging.scope.getByRole('button', { name: names.more, exact: true }).click();
    await paging.scope.getByText(names.catalogChanged, { exact: true }).waitFor({ state: 'visible' });
    assert.equal(await paging.scope.getByRole('option').count(), 0);
    await paging.scope.getByRole('button', { name: names.retry, exact: true }).click();
    await paging.scope.locator('[role=option][id$="-option-100"]').waitFor({ state: 'visible' });
    await paging.input.press('Escape'); checks.add('catalog-revision-change');
    await choose(page, locale, 'locality', '11');
    await page.locator('[data-location-selected=locality] bdi').first().waitFor();
    await settled(page);
    const before = await currentSelection(page), requests = harness.observed.requests;
    const other = locale === 'en' ? 'fa-IR' : 'en';
    await page.getByTestId(`locale-${other}`).click(); await selection(page, before);
    await settled(page);
    assert.equal(harness.observed.requests, requests, 'Language change replayed geography API work');
    await page.getByTestId(`locale-${locale}`).click(); await selection(page, before);
    await screenshot(page, directory, locale, 'desktop'); journeys.push('desktop');
    checks.add('rtl-language-preserves-selection');
    await page.setViewportSize({ width: 390, height: 844 });
    const opener = page.locator('[data-location-field=province]').getByRole('button', { name: names.province, exact: true });
    const mobile = await openPicker(page, locale, 'province', true);
    for (let index = 0; index < 10; index++) {
      await page.keyboard.press('Tab');
      assert(await mobile.scope.evaluate((dialog) => dialog.contains(document.activeElement)), 'Mobile dialog focus escaped');
    }
    await mobile.input.focus(); await mobile.input.press('Escape');
    await mobile.scope.waitFor({ state: 'hidden' });
    assert(await opener.evaluate((element) => element === document.activeElement), 'Mobile dialog focus did not return to its opener');
    await choose(page, locale, 'province', '2', true);
    await selection(page, { country: 'IR', province_id: '2' });
    await choose(page, locale, 'locality', '20', true);
    await selection(page, { country: 'IR', province_id: '2', locality_id: '20' });
    const skipDialog = await openPicker(page, locale, 'locality', true);
    await skipDialog.scope.getByRole('button', { name: names.skip, exact: true }).click();
    await selection(page, { country: 'IR', province_id: '2' });
    checks.add('mobile-dialog-focus');
    const boundsDialog = await openPicker(page, locale, 'locality', true);
    await screenshot(page, directory, locale, 'mobile'); journeys.push('mobile');
    for (const viewport of [{ width: 320, height: 568 }, { width: 320, height: 256 }, { width: 430, height: 800 }]) {
      await page.setViewportSize(viewport); await boundsDialog.input.focus(); await settled(page);
      assert.deepEqual(await page.evaluate(geographyBounds), []);
    }
    await boundsDialog.scope.getByRole('button', { name: names.close, exact: true }).click();
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.getByTestId('theme').click();
    const dark = await openPicker(page, locale, 'locality', false);
    await screenshot(page, directory, locale, 'dark');
    await dark.input.press('Escape');
    checks.add('responsive-touch-bounds'); checks.add('masked-screenshots');
    // Separate real API probes retain only status/counts. They never record
    // query text, response bodies, cursors, IDs, cookies, traces or storage.
    for (const path of ['/api/v1/geography/provinces?country=IR&limit=51',
      '/api/v1/geography/localities?country=IR&province_id=10', '/api/v1/geography/provinces?country=XX']) {
      const response = await context.request.get(harness.origin + path); assert.equal(response.status(), 400); await response.dispose();
    }
    let limited = false;
    const burstStarted = Date.now();
    // A fixed-minute bucket may roll over during this probe. Bound the probe to
    // thirty seconds and at most two full budgets without clearing Redis state.
    for (let index = 0; index <= 240; index++) {
      const response = await context.request.get(harness.origin + '/api/v1/geography/provinces?country=IR');
      if (response.status() === 429) { assert.equal(response.headers()['retry-after'], '60'); limited = true; }
      else assert.equal(response.status(), 200);
      await response.dispose();
      if (limited) break;
    }
    assert(limited && Date.now() - burstStarted < 30_000, 'Real Redis geography limiter did not enforce its bounded probe');
    checks.add('real-rate-limit-retry-after');
    assert(harness.observed.real > 0 && harness.observed.statuses[409] > 0 && harness.observed.statuses[429] > 0);
    checks.add('anonymous-real-api');
    const storage = await page.evaluate(async () => ({ local: localStorage.length, session: sessionStorage.length,
      databases: (await indexedDB.databases()).length, registrations: (await navigator.serviceWorker.getRegistrations()).length }));
    assert.deepEqual(storage, { local: 0, session: 0, databases: 0, registrations: 0 });
    assert.deepEqual(await context.cookies(), []);
    assert.equal(failures.size, 0, 'Geography browser console/network privacy failed');
    checks.add('private-storage-console-network');
    assert.deepEqual([...checks].sort(), [...geographyLocaleChecks].sort());
    assert.deepEqual(journeys, geographyJourneys);
    await harness.assertClean();
    return { locale, journeys, checks: [...checks], services: structuredClone(harness.observed) };
  } finally { await close(); }
}

export async function runGeographyBrowser({ directory = process.env.GEOGRAPHY_BROWSER_ARTIFACT_DIR,
  start = startGeographyHarness, validate = validateGeographyBrowser, identify = acceptanceIdentity, guard = guardBrowserFailures } = {}) {
  const report = { schema: 1, kind: 'geography-browser', scope: 'full', status: 'failed', cleanup: { completed: false },
    exit: 1, failed: 1, skipped: 0, tests: 0, checks: [], localeEvidence: [], binaryEvidence: {} };
  const output = directory && resolve(directory, 'geography-evidence.json');
  if (directory) { await mkdir(directory, { recursive: true }); await rm(output, { force: true }); }
  let harness, unguard = () => {}, interrupted = false, failure;
  try {
    report.identity = await identify();
    for (const locale of geographyLocales) {
      harness = await start();
      unguard = guard(async () => { interrupted = true; await harness.close(); });
      assertIdentity(harness.identity, report.identity);
      report.localeEvidence.push(await validate(harness, locale, directory));
      if (Object.keys(report.binaryEvidence).length) assert.deepEqual(harness.binaryEvidence, report.binaryEvidence, 'Locale builds used different geography binaries');
      else report.binaryEvidence = harness.binaryEvidence;
      report.cleanup = await harness.close(); assert.equal(report.cleanup?.completed, true, 'Geography teardown was not confirmed');
      harness = undefined; unguard(); unguard = () => {};
    }
    assert(!interrupted, 'Geography acceptance was interrupted');
    assertIdentity(await identify(), report.identity);
    report.status = 'passed'; report.exit = 0; report.failed = 0;
    report.checks = [...geographyChecks]; report.tests = report.checks.length;
    assertGeographyReport(report, report.identity);
    if (output) await writeFile(output, JSON.stringify(report) + '\n');
    return report;
  } catch (error) { failure = error; }
  finally {
    if (harness) try { await harness.close(); } catch (error) { failure ||= error; }
    unguard();
  }
  throw failure;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { const report = await runGeographyBrowser(); console.log(JSON.stringify({ kind: report.kind, status: report.status, tests: report.tests, skipped: report.skipped, cleanup: report.cleanup })); }
  catch (error) { console.error(browserFailure(error, 'geography-browser')); process.exitCode = 1; }
}
