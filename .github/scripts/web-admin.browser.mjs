import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, readlink, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { browserFailure, guardBrowserFailures, startPortalHarness } from './portal-harness.mjs';
import {
  addAuthenticator, api, clean, hidePortal, newContext, operationResponse as waitForOperation, signIn, visit,
} from './web-portal.browser.mjs';

let checkpoint = 'startup';
const routes = ['/admin', '/admin/users', '/admin/audit-logs', '/admin/integrity'];
const script = fileURLToPath(import.meta.url);
const workspace = resolve(dirname(script), '../..');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const statusRoute = /^\/api\/v1\/admin\/users\/[^/]+\/status\/?$/;

export function observeStatusPatches(cdp, origin) {
  const attempts = [];
  let reconciliation = false;
  let invalid = false;
  const outgoing = ({ requestId, request }) => {
    try {
      if (request.method !== 'PATCH' || !statusRoute.test(new URL(request.url).pathname)) return;
      const headers = new Headers(request.headers);
      const claims = JSON.parse(Buffer.from((headers.get('DPoP') || '').split('.')[1], 'base64url').toString());
      assert(typeof requestId === 'string' && requestId.length > 0);
      assert(new URL(request.url).origin === origin && typeof request.postData === 'string');
      assert(claims.nonce === undefined || typeof claims.nonce === 'string');
      attempts.push({
        id: requestId, reconciliation, status: null, challenge: null,
        followsChallenge: attempts.length === 1 && attempts[0].status === 401 && attempts[0].challenge !== null,
        nonce: claims.nonce === undefined ? null : digest(claims.nonce),
        logicalRequest: digest(JSON.stringify([request.url, request.postData, headers.get('X-Portal-Session'), headers.get('X-Step-Up-Auth')])),
      });
    } catch { invalid = true; }
  };
  cdp.on('Network.requestWillBeSent', outgoing);
  return {
    get count() {
      assert(!invalid, 'Status PATCH observation failed');
      return attempts.length;
    },
    response(event, body = '') {
      const attempt = attempts.find(({ id }) => id === event.networkId);
      assert(attempt && attempt.status === null, 'Unmatched or repeated status PATCH response');
      attempt.status = event.responseStatusCode;
      const headers = new Headers();
      for (const { name, value } of event.responseHeaders || []) headers.append(name, value);
      const nonce = headers.get('DPoP-Nonce');
      if (attempt.status === 401 && nonce && /^[A-Za-z0-9._~-]{1,1024}$/.test(nonce) &&
          /^DPoP[ \t]+error="use_dpop_nonce"$/i.test(headers.get('WWW-Authenticate') || '')) {
        assert(Buffer.byteLength(body) <= 4096, 'Oversized nonce challenge');
        if (JSON.parse(body)?.error === 'use_dpop_nonce') attempt.challenge = digest(nonce);
      }
    },
    reconcile() { reconciliation = true; },
    assertLostResponse() {
      assert(!invalid, 'Status PATCH observation failed');
      assert(attempts.length === 1 || attempts.length === 2, 'Unexpected status PATCH attempt, including a failed replay');
      assert(attempts.every((attempt) => !attempt.reconciliation), 'Current-state reconciliation sent a status PATCH');
      if (attempts.length === 2) {
        const [initial, retry] = attempts;
        assert(initial.status === 401 && initial.challenge && initial.nonce === null,
          'Only an initial explicit pre-handler DPoP nonce challenge permits a retry');
        assert(retry.followsChallenge && retry.nonce === initial.challenge && retry.logicalRequest === initial.logicalRequest,
          'Nonce retry changed the logical mutation or did not echo the challenge');
      }
      assert(attempts.at(-1).status === 204 && !attempts.at(-1).challenge,
        'Expected exactly one deliberately lost real 204');
      return { outgoingStatusPatches: attempts.length, preHandlerNonceRetries: attempts.length - 1, reconciliationStatusPatches: 0 };
    },
    close() { cdp.off('Network.requestWillBeSent', outgoing); attempts.length = 0; },
  };
}

export function observeAdminMarkers(context, harness, markers, failures) {
  harness.secrets.push(...Object.values(markers));
  context.on('request', (request) => {
    try {
      const values = Object.values(markers);
      const contains = (text) => values.some((value) => text.includes(value) || text.includes(encodeURIComponent(value)));
      assert(!contains(request.url()) && !contains(JSON.stringify(request.headers())));
      const body = request.postData() || '';
      if (!contains(body)) return;
      const url = new URL(request.url());
      assert(url.origin === harness.origin && statusRoute.test(url.pathname) && request.method() === 'PATCH');
      const { reason, ...rest } = JSON.parse(body);
      assert(reason === markers.reason && !contains(JSON.stringify(rest)));
    } catch { failures.push('Controlled admin private marker escaped its permitted request body'); }
  });
}

async function assertAdminPrivacy(page, observed, markers) {
  await clean(page, observed);
  assert(await page.evaluate((values) => {
    const state = JSON.stringify(history.state) || '';
    return values.every((value) => !state.includes(value) && !state.includes(encodeURIComponent(value)));
  }, Object.values(markers)), 'Controlled admin private marker entered browser history state');
}

export async function adminWorktreeIdentity() {
  const git = (args) => {
    const result = spawnSync('git', args, { cwd: workspace, maxBuffer: 64 * 1024 * 1024, timeout: 15_000 });
    assert(!result.error && result.status === 0, 'Cannot identify the tested worktree');
    return result.stdout;
  };
  const head = git(['rev-parse', 'HEAD']).toString().trim();
  assert(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(head), 'Invalid tested worktree revision');
  const untracked = createHash('sha256');
  for (const path of git(['ls-files', '--others', '--exclude-standard', '-z']).toString().split('\0').filter(Boolean).sort()) {
    const absolute = resolve(workspace, path);
    const stat = await lstat(absolute);
    untracked.update(JSON.stringify([path, stat.mode]));
    untracked.update(stat.isSymbolicLink() ? await readlink(absolute) : await readFile(absolute));
  }
  const status = git(['status', '--porcelain=v1', '--untracked-files=all', '-z']);
  const diff = ['--binary', '--no-ext-diff', '--no-textconv', '--no-color'];
  return {
    root: await realpath(workspace), head, dirty: status.length > 0,
    statusSHA256: digest(status),
    stagedDiffSHA256: digest(git(['diff', '--cached', ...diff])),
    unstagedDiffSHA256: digest(git(['diff', ...diff])),
    untrackedSHA256: untracked.digest('hex'),
  };
}

export function adminInvocation({ argv = process.argv, execArgv = process.execArgv, declared = process.env.ADMIN_BROWSER_INVOCATION } = {}) {
  assert(argv.length === 2 && resolve(argv[1]) === script && execArgv.length === 0,
    'Admin browser evidence requires the exact script invocation without extra arguments');
  const allowed = [
    'npm exec -- nx run web:test-admin-browser --skipNxCache',
    `npm exec -- nx exec -p web -- node ${script}`,
    `npm exec -- nx exec -p web -- node "${script}"`,
    'node .github/scripts/web-admin.browser.mjs',
    `node ${script}`,
  ];
  assert(declared === undefined || allowed.includes(declared), 'Unrecognized declared admin browser invocation');
  return {
    executable: process.execPath, arguments: argv.slice(1), cwd: process.cwd(),
    declaredOuterCommand: declared ?? null,
  };
}

export async function runAdminBrowser({
  directory = process.env.ADMIN_BROWSER_ARTIFACT_DIR,
  start = startPortalHarness, validate = validateAdmin, identity = adminWorktreeIdentity,
  invocation = adminInvocation, guard = guardBrowserFailures,
} = {}) {
  checkpoint = 'startup';
  const run = { schemaVersion: 1, runID: randomBytes(16).toString('hex'), startedAt: new Date().toISOString() };
  const root = directory ? resolve(directory) : null;
  const artifactDirectory = root ? resolve(root, run.runID) : undefined;
  const evidenceFile = root ? resolve(root, 'admin-evidence.json') : null;
  let harness, releaseGuard, closePromise, failure, evidence;
  let assertions = 'not-complete';
  let teardown = 'not-confirmed';
  let interrupted = false;
  let publication = Promise.resolve();
  const publish = (report) => {
    publication = publication.catch(() => {}).then(async () => {
      assert(report.status !== 'passed' || !interrupted, 'Interrupted browser run cannot publish success');
      const text = JSON.stringify(report, null, 2) + '\n';
      assert(!harness?.secrets.some((value) => value &&
        (text.includes(value) || text.includes(JSON.stringify(value).slice(1, -1)))), 'Private fixture data entered saved evidence');
      if (!evidenceFile) return;
      const temporary = resolve(root, `admin-evidence-${run.runID}.tmp`);
      try {
        await writeFile(temporary, text, { flag: 'wx', mode: 0o600 });
        assert(report.status !== 'passed' || !interrupted, 'Interrupted browser run cannot publish success');
        await rename(temporary, evidenceFile);
      } finally { await rm(temporary, { force: true }); }
    });
    return publication;
  };
  const close = () => closePromise ||= (async () => {
    if (!harness) return;
    teardown = 'failed';
    const result = await harness.close();
    assert(result?.completed === true, 'Disposable harness teardown was not affirmatively completed');
    teardown = 'completed';
  })();
  if (root) {
    await mkdir(root, { recursive: true });
    // Invalidate old success before worktree checks, startup, or any assertions.
    await rm(evidenceFile, { force: true });
    await mkdir(artifactDirectory);
  }
  try {
    try {
      await publish({ ...run, status: 'running', exitStatus: null, assertions, teardown });
      run.invocation = { ...invocation(), environment: root ? { ADMIN_BROWSER_ARTIFACT_DIR: root } : {} };
      run.worktree = await identity();
      if (root) run.artifactDirectory = artifactDirectory;
      harness = await start({ admin: true });
      assert(/^[a-f0-9]{32}$/.test(harness.runID), 'Missing run-owned service identifier');
      run.serviceRunID = harness.runID;
      releaseGuard = guard(async () => {
        interrupted = true;
        await close().catch(() => {});
        await publish({ ...run, status: 'failed', exitStatus: 1, assertions, teardown,
          finishedAt: new Date().toISOString(), failure: 'Browser callback failed; sensitive details suppressed.' });
      });
      evidence = await validate(harness, { artifactDirectory });
      assertions = 'passed';
    } catch (error) { failure = error; }
    try { await close(); } catch (error) { failure ||= error; }
    if (!failure) {
      try {
        assert(!interrupted && !process.exitCode, 'Browser run was interrupted');
        assert.deepEqual(await identity(), run.worktree, 'Tested worktree changed during the browser run');
      } catch (error) { failure = error; }
    }
    let report = {
      ...(!failure ? evidence : {}),
      ...run, status: failure ? 'failed' : 'passed', exitStatus: failure ? 1 : 0,
      assertions, teardown, finishedAt: new Date().toISOString(),
      ...(failure ? { failure: browserFailure(failure, checkpoint) } : { worktreeMatchesAtFinish: true }),
    };
    try { await publish(report); } catch (error) {
      failure ||= error;
      report = { ...run, status: 'failed', exitStatus: 1, assertions, teardown,
        finishedAt: new Date().toISOString(), failure: browserFailure(failure, checkpoint) };
      // A failed evidence write is also a failed run, never a stale success.
      try { await publish(report); } catch {
        if (evidenceFile) await rm(evidenceFile, { force: true });
      }
    }
    if (failure) { harness?.diagnostics(); throw failure; }
    return report;
  } finally { releaseGuard?.(); }
}

function deferred() {
  let resolve;
  const promise = new Promise((finish) => { resolve = finish; });
  return { promise, resolve };
}

async function open(page, harness, path) {
  const response = await visit(page, harness.origin, path);
  await page.getByTestId('admin-ready').waitFor({ state: 'visible' });
  return response;
}

async function confirmForm(page, action = 'Suspend', method = 'passkey', harness, fixture) {
  await page.getByRole('button', { name: action, exact: true }).click();
  const dialog = page.getByTestId('stepup-dialog');
  await dialog.waitFor({ state: 'visible' });
  assert(await dialog.evaluate((element) => element instanceof HTMLDialogElement && element.open));
  assert.equal(await dialog.getByLabel('Moderation reason', { exact: true }).count(), 0);
  await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
  if (method === 'totp') {
    await dialog.getByRole('button', { name: 'Use authenticator code', exact: true }).click();
    const current = harness.fixture('totp-code', { user_id: fixture.user_id });
    await dialog.getByLabel('Authenticator code', { exact: true }).fill(current.code);
    await dialog.getByRole('button', { name: 'Verify code', exact: true }).click();
  } else {
    await dialog.getByRole('button', { name: 'Verify with a passkey', exact: true }).click();
  }
  await dialog.getByLabel('Moderation reason', { exact: true }).waitFor({ state: 'visible' });
  assert(await dialog.getByLabel('Moderation reason', { exact: true }).evaluate((element) => element === document.activeElement));
  return dialog;
}

async function finalSubmit(dialog, reason, action = 'suspend') {
  await dialog.getByLabel('Moderation reason', { exact: true }).fill(reason);
  await dialog.getByRole('checkbox', { name: /I reviewed the account/ }).check();
  await dialog.getByRole('button', { name: `Confirm ${action}`, exact: true }).click();
}

export function adminAppearance({ focusedOnly = false } = {}) {
  // Measure settled theme/focus colors rather than a transition's intermediate frame.
  for (const animation of document.getAnimations()) {
    if (animation instanceof CSSTransition) animation.finish();
  }
  const failures = new Set();
  const modal = document.querySelector('dialog[open]');
  const shown = (element) => element.getClientRects().length &&
    element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) &&
    !element.closest('[hidden], [inert]') && !element.matches('.sr-only:not(:focus)');
  // Match the production CSP suite's alpha-composited sRGB contrast checks.
  const color = (value) => {
    const match = value.match(/^rgba?\(([^)]+)\)$/);
    if (!match) throw new Error('Unsupported computed admin color');
    const channels = match[1].split(/[,\s/]+/).map(Number);
    if (!channels.every(Number.isFinite)) throw new Error('Invalid computed admin color');
    return [...channels.slice(0, 3), channels[3] ?? 1];
  };
  const composite = (foreground, backdrop) => foreground.slice(0, 3)
    .map((channel, index) => channel * foreground[3] + backdrop[index] * (1 - foreground[3]));
  const background = (element) => element
    ? composite(color(getComputedStyle(element).backgroundColor), background(element.parentElement))
    : [255, 255, 255];
  const luminance = (rgb) => rgb.reduce((sum, value, index) => {
    const channel = value / 255;
    return sum + (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4) *
      [0.2126, 0.7152, 0.0722][index];
  }, 0);
  const ratio = (foreground, backdrop) => {
    const a = luminance(composite(foreground, backdrop));
    const b = luminance(backdrop);
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  };
  if (focusedOnly) {
    const element = document.activeElement;
    if (!element || !shown(element) || !element.matches(':focus-visible')) {
      return ['Admin keyboard target is not visibly focused'];
    }
    const style = getComputedStyle(element);
    const backdrop = background(element.parentElement);
    const ring = [...style.boxShadow.matchAll(/(rgba?\([^)]+\)) 0px 0px 0px ([\d.]+)px/g)]
      .some((match) => Number(match[2]) >= 2 && ratio(color(match[1]), backdrop) >= 3);
    const outline = !['none', 'hidden'].includes(style.outlineStyle) &&
      Number.parseFloat(style.outlineWidth) >= 2 && ratio(color(style.outlineColor), backdrop) >= 3;
    if (!ring && !outline) failures.add('Admin keyboard target lacks a 2px, 3:1 focus indicator');
    const rect = element.getBoundingClientRect();
    const vertical = rect.height <= innerHeight
      ? rect.top >= -1 && rect.bottom <= innerHeight + 1
      : Math.min(rect.bottom, innerHeight) - Math.max(rect.top, 0) >= 44;
    if (rect.left < -1 || rect.right > innerWidth + 1 || !vertical)
      failures.add('Admin keyboard target is outside the viewport');
    for (let parent = element.parentElement; parent; parent = parent.parentElement) {
      const style = getComputedStyle(parent);
      const bounds = parent.getBoundingClientRect();
      if ((/(hidden|clip|auto|scroll)/.test(style.overflowX) && (rect.left < bounds.left - 1 || rect.right > bounds.right + 1)) ||
          (/(hidden|clip|auto|scroll)/.test(style.overflowY) && (rect.top < bounds.top - 1 || rect.bottom > bounds.bottom + 1)))
        failures.add('Admin keyboard target is clipped by a scrolling or clipping ancestor');
    }
    if (modal && !modal.contains(element)) failures.add('Admin modal lost keyboard containment');
    return [...failures];
  }
  if (document.documentElement.scrollWidth > innerWidth + 1)
    failures.add('Admin page has document-wide horizontal overflow');
  if (modal) {
    const rect = modal.getBoundingClientRect();
    if (rect.top < -1 || rect.bottom > innerHeight + 1)
      failures.add('Admin modal does not fit the available viewport height');
  }
  for (const element of (modal || document).querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea')) {
    if (!shown(element) || element.matches(':disabled')) continue;
    const target = element.matches('input[type=checkbox]')
      ? Array.from(element.labels || []).find(shown) : element;
    if (!target) { failures.add('Admin checkbox lacks a visible associated label'); continue; }
    const rect = target.getBoundingClientRect();
    if (rect.height < 44 || rect.width < 44) failures.add('Admin interaction target is below 44px');
    if (element.matches('input, select, textarea') &&
        ratio(color(getComputedStyle(element).color), background(element)) < 4.5)
      failures.add('Admin field text contrast is below 4.5:1');
  }
  const walker = document.createTreeWalker(modal || document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const element = node.parentElement;
    if (!node.textContent.trim() || !element || !shown(element) ||
        element.closest('script, style, noscript, [aria-hidden="true"], :disabled, .sr-only')) continue;
    const style = getComputedStyle(element);
    const size = Number.parseFloat(style.fontSize);
    const large = size >= 24 || (size >= 18.66 && Number.parseInt(style.fontWeight, 10) >= 700);
    if (ratio(color(style.color), background(element)) < (large ? 3 : 4.5))
      failures.add('Admin text contrast is below its readable-size threshold');
  }
  return [...failures];
}

async function layout(page, name, evidence, artifactDirectory) {
  for (const viewport of [{ width: 1280, height: 900 }, { width: 320, height: 900 }, { width: 320, height: 256 }]) {
    for (const dark of [false, true]) {
      await page.setViewportSize(viewport);
      await page.evaluate((enabled) => document.documentElement.classList.toggle('dark', enabled), dark);
      assert.deepEqual(await page.evaluate(adminAppearance), [], 'Admin pointer targets, contrast or reflow regressed');
      const modal = page.locator('dialog[open]');
      if (await modal.count()) {
        const stops = await modal.locator('a[href], button:enabled, input:enabled, select:enabled, textarea:enabled').count();
        assert(stops > 0, 'Admin modal has no keyboard controls');
        for (let index = 0; index < stops; index++) {
          await page.keyboard.press('Tab');
          assert.deepEqual(await page.evaluate(adminAppearance, { focusedOnly: true }), [], 'Admin modal keyboard focus regressed');
        }
      } else {
        const controls = page.locator('table tbody a[href]:visible, table tbody button:enabled:visible');
        if (await controls.count()) {
          assert(await page.locator('table').evaluateAll((tables) => tables.every((table) => {
            const headers = [...table.querySelectorAll('thead th')];
            return headers.length > 0 && headers.every((header) => header.scope === 'col');
          })), 'Admin table lacks semantic column headers');
          await controls.first().focus();
          await page.keyboard.press('Shift+Tab');
          assert.deepEqual(await page.evaluate(adminAppearance, { focusedOnly: true }), [], 'Admin table entry focus regressed');
          for (let index = 0; index < await controls.count(); index++) {
            await page.keyboard.press('Tab');
            assert(await controls.nth(index).evaluate((element) => element === document.activeElement), 'Admin table keyboard order regressed');
            const failures = await page.evaluate(adminAppearance, { focusedOnly: true });
            if (failures.length) console.error(JSON.stringify({ check: 'admin-table-focus', viewport, dark, failures }));
            assert.deepEqual(failures, [], 'Admin table keyboard focus regressed');
          }
        }
      }
      if (artifactDirectory) {
        await page.screenshot({
          path: resolve(artifactDirectory, `${name}-${viewport.width}x${viewport.height}-${dark ? 'dark' : 'light'}.png`),
          fullPage: true,
          animations: 'disabled',
          mask: [page.locator('tbody, main dd, main .font-mono, input, textarea')],
        });
      }
      evidence.layouts++;
    }
  }
  evidence.headlessZoomEquivalent = '320x256 CSS viewport; not native browser zoom';
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.evaluate(() => document.documentElement.classList.remove('dark'));
}

async function queryFault(page, path, action, response) {
  const pattern = `**${path}*`;
  let requests = 0;
  let interceptionFailed = false;
  const arrived = deferred();
  const timer = setTimeout(() => arrived.resolve(false), 15_000);
  const intercept = async (route) => {
    requests++;
    try {
      await route.fulfill({ status: response.status, contentType: 'application/json', headers: {
        'Cache-Control': 'private, no-store', 'Referrer-Policy': 'no-referrer', ...response.headers,
      }, body: response.body });
      arrived.resolve(true);
    } catch {
      interceptionFailed = true;
      arrived.resolve(false);
      await route.abort('failed').catch(() => {});
    }
  };
  await page.route(pattern, intercept);
  try {
    await action();
    assert(await arrived.promise, 'The expected faulted read did not arrive');
    await page.getByRole('main').getByRole('alert').last().waitFor({ state: 'visible' });
    assert.equal(interceptionFailed, false, 'Read-failure interception failed');
    assert.equal(requests, 1, 'A failed read was silently retried');
    assert.equal(await page.getByTestId('admin-account-row').count(), 0);
  } finally { clearTimeout(timer); await page.unroute(pattern, intercept); }
}

export async function validateAdmin(harness, { artifactDirectory } = {}) {
  const evidence = { checks: [], layouts: 0, nativeHiddenTabObserved: false, nativeBfcacheRestoreObserved: false };
  const markerID = randomBytes(16).toString('hex');
  const markers = Object.fromEntries(['reason', 'cancelledDraft', 'backgroundDraft', 'expiredDraft']
    .map((kind) => [kind, `admin-private-${kind}-${markerID}`]));
  const browser = await chromium.launch({ channel: 'chromium', args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`] });
  const contexts = [];
  const actors = {};
  async function operationResponse(page, path, method) {
    // Chromium can discard finished fetch bodies. Capture the same upstream
    // response once, in bounded memory, without issuing another request.
    const body = method === 'GET' || path === '/api/v1/admin/users/lookup'
      ? harness.captureJSON(path, method, 200) : null;
    const response = await waitForOperation(page, path, method);
    return {
      status: () => response.status(),
      url: () => response.url(),
      request: () => response.request(),
      json: () => body && response.status() === 200 ? body : response.json(),
    };
  }
  try {
    checkpoint = 'admin-bootstrap';
    for (const role of ['ordinary', 'support', 'moderator', 'dpo', 'super_admin', 'combined']) {
      const fixture = harness.fixture('admin-seed', { role });
      const { context, observed } = await newContext(browser, harness);
      contexts.push(context);
      observeAdminMarkers(context, harness, markers, observed.failures);
      const page = await context.newPage();
      const authenticator = await addAuthenticator(page, fixture.credentials[0]);
      await authenticator.cdp.send('Network.enable', { maxPostDataSize: 64 * 1024 });
      await signIn(page, harness.origin);
      actors[role] = { fixture, page, context, observed, authenticator };
    }
    const target = actors.ordinary.fixture;
    const pending = harness.fixture('admin-seed', { role: 'ordinary', status: 'pending_verification' });
    const deleting = harness.fixture('admin-seed', { role: 'ordinary', status: 'pending_deletion' });
    const audit = harness.fixture('admin-audit', { user_id: target.user_id, scenario: 'large-payload' });
    assert(typeof audit.payload_marker === 'string' && audit.payload_marker.length > 20, 'Missing controlled audit-payload marker');
    markers.auditPayload = audit.payload_marker;
    const moderator = actors.moderator.page;
    const dpo = actors.dpo.page;
    const support = actors.support.page;
    const ordinary = actors.ordinary.page;
    const statusPath = `/api/v1/admin/users/${target.user_id}/status`;
    const detailPath = `/admin/users/${target.user_id}`;

    for (const role of ['support', 'moderator', 'dpo', 'super_admin', 'combined']) {
      const { page } = actors[role];
      await open(page, harness, '/admin');
      const caps = await api(page, '/api/v1/admin/capabilities');
      assert.equal(caps.status, 200);
      assert.deepEqual(Object.keys(caps.body).sort(), ['capabilities', 'limits']);
      const access = caps.body.capabilities;
      assert.equal(access.users_read, ['support', 'moderator', 'combined'].includes(role));
      assert.equal(access.users_pii, ['moderator', 'combined'].includes(role));
      assert.equal(access.users_lookup, access.users_pii);
      assert.equal(access.users_status_write, access.users_pii);
      assert.equal(access.audit_logs_read, ['dpo', 'combined'].includes(role));
      assert.equal(access.audit_chain_verify, ['dpo', 'super_admin', 'combined'].includes(role));
      assert.equal(access.ledger_verify, access.audit_chain_verify);
      assert.equal(caps.body.limits.chain_verify_max_limit, 5);
      if (!access.users_read) assert.equal(await page.getByRole('link', { name: 'Accounts', exact: true }).count(), 0);
      if (!access.audit_logs_read) assert.equal(await page.getByRole('link', { name: 'Audit logs', exact: true }).count(), 0);
    }
    await visit(ordinary, harness.origin, '/admin');
    await ordinary.getByRole('main').getByRole('alert').waitFor({ state: 'visible' });
    assert.equal(await ordinary.getByTestId('admin-ready').count(), 0);
    assert.equal((await api(ordinary, '/api/v1/users/me')).status, 200, 'Admin denial signed out an ordinary account');
    for (const path of ['/api/v1/admin/users', '/api/v1/admin/capabilities'])
      assert.equal((await api(ordinary, path)).status, 403);
    evidence.checks.push('live capability matrix, combined grants, ordinary denial without normal-session logout');

    checkpoint = 'admin-no-script';
    const noScript = await browser.newContext({ javaScriptEnabled: false, serviceWorkers: 'block' });
    contexts.push(noScript);
    await noScript.addCookies(await actors.moderator.context.cookies(harness.origin));
    const staticPage = await noScript.newPage();
    for (const path of [...routes, detailPath]) {
      const response = await visit(staticPage, harness.origin, path);
      const html = await response.text();
      assert(!html.includes(target.email) && !Object.values(markers).some((marker) => html.includes(marker)));
      assert.equal(await staticPage.locator('form, input, textarea, table').count(), 0);
      assert.equal(await staticPage.getByTestId('admin-ready').count(), 0);
    }
    await staticPage.close();
    const cookieOnly = await actors.moderator.context.newPage();
    await visit(cookieOnly, harness.origin, '/login');
    assert.equal(await cookieOnly.evaluate(async () => (await fetch('/api/v1/admin/capabilities', { credentials: 'same-origin' })).status), 401);
    await cookieOnly.close();
    evidence.checks.push('all admin documents have nonce CSP and non-sensitive no-JavaScript shells; cookies without DPoP fail');

    checkpoint = 'admin-directory';
    await open(support, harness, '/admin/users');
    assert.equal(await support.getByLabel('Exact email', { exact: true }).count(), 0);
    const list = operationResponse(support, '/api/v1/admin/users', 'GET');
    await support.getByRole('button', { name: 'Apply filters', exact: true }).click();
    const supportBody = await (await list).json();
    assert(supportBody.items.length > 0 && supportBody.items.length <= 5);
    assert(supportBody.items.every((item) => !('email' in item) && typeof item.lifecycle_revision === 'string'));
    await support.getByTestId('admin-account-row').first().waitFor();
    assert.equal(await support.getByRole('columnheader', { name: 'Email', exact: true }).count(), 0);
    const next = operationResponse(support, '/api/v1/admin/users', 'GET');
    await support.getByRole('button', { name: 'Next page', exact: true }).click();
    assert.equal((await (await next).json()).offset, 5);
    await layout(support, 'accounts', evidence, artifactDirectory);
    const skip = support.getByRole('link', { name: 'Skip to admin content', exact: true });
    await skip.focus();
    await support.keyboard.press('Tab');
    await support.keyboard.press('Shift+Tab');
    assert(await skip.evaluate((element) => element === document.activeElement), 'Keyboard did not reach the admin skip link');
    assert.deepEqual(await support.evaluate(adminAppearance, { focusedOnly: true }), [], 'Admin skip-link focus regressed');
    const accessAfterSkip = waitForOperation(support, '/api/v1/admin/capabilities', 'GET');
    await support.keyboard.press('Enter');
    assert.equal((await accessAfterSkip).status(), 200);
    await support.getByTestId('admin-ready').waitFor();
    assert.equal(new URL(support.url()).hash, '#portal-content');
    assert(await support.getByRole('main').evaluate((element) => element === document.activeElement), 'Admin skip link did not focus main content');
    assert.equal(await support.getByTestId('admin-account-row').count(), 0, 'Skip-link revalidation restored a private query without explicit submission');
    evidence.checks.push('keyboard skip link focuses main after real capability revalidation; table controls are traversed by Tab with computed visible focus');

    await open(moderator, harness, '/admin/users');
    const lookup = operationResponse(moderator, '/api/v1/admin/users/lookup', 'POST');
    await moderator.getByLabel('Exact email', { exact: true }).fill(target.email);
    await moderator.getByRole('button', { name: 'Find account', exact: true }).click();
    const found = await lookup;
    assert.equal(new URL(found.url()).search, '');
    assert.deepEqual(found.request().postDataJSON(), { email: target.email });
    assert.equal((await found.json()).items[0].id, target.user_id);
    await moderator.getByRole('link', { name: `View account ${target.user_id}`, exact: true }).click();
    await moderator.getByTestId('admin-ready').waitFor();
    await moderator.getByRole('heading', { name: target.user_id, exact: true }).waitFor();
    const supportSession = (await api(support, '/api/v1/users/me')).body.session.id;
    assert.equal((await api(support, '/api/v1/admin/users/lookup', { method: 'POST', body: { email: target.email }, sessionID: supportSession })).status, 403);
    assert.equal((await api(moderator, '/api/v1/admin/users?limit=1&limit=2')).status, 400);
    assert.equal((await api(moderator, '/api/v1/admin/users?email=not-an-identity')).status, 400);
    evidence.checks.push('PII projection, explicit body-only lookup, bounded offset pages, server query-key rejection');

    checkpoint = 'admin-moderation';
    const cdp = actors.moderator.authenticator.cdp;
    const cancelledPatches = observeStatusPatches(cdp, harness.origin);
    let dialog;
    try {
      dialog = await confirmForm(moderator);
      for (let index = 0; index < 10; index++) {
        await moderator.keyboard.press('Tab');
        assert(await dialog.evaluate((element) => element.contains(document.activeElement)), 'Native modal lost its focus trap');
      }
      const reason = await dialog.getByLabel('Moderation reason', { exact: true }).elementHandle();
      await reason.fill(markers.cancelledDraft);
      await assertAdminPrivacy(moderator, actors.moderator.observed, markers);
      await layout(moderator, 'confirmation', evidence, artifactDirectory);
      await moderator.keyboard.press('Escape');
      await dialog.waitFor({ state: 'hidden' });
      assert(await reason.evaluate((element) => element.value === ''), 'Cancelled reason remained on the detached input');
      await reason.dispose();
      assert(await moderator.getByRole('button', { name: 'Suspend', exact: true }).evaluate((element) => element === document.activeElement));
      assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'active');
      assert.equal(cancelledPatches.count, 0, 'Pre-send cancellation transmitted a status PATCH');
    } finally { cancelledPatches.close(); }

    // The server, not visible status text, protects a pin from a profile/ABA edit.
    dialog = await confirmForm(moderator);
    harness.fixture('admin-revision', { user_id: target.user_id });
    const conflict = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    assert.equal((await conflict).status(), 409);
    await moderator.getByRole('alert').filter({ hasText: /account changed/i }).waitFor();
    assert.equal(await moderator.getByLabel('Moderation reason', { exact: true }).count(), 0);
    await moderator.getByRole('button', { name: 'Read current state', exact: true }).click();
    await moderator.getByRole('button', { name: 'Suspend', exact: true }).waitFor();

    dialog = await confirmForm(moderator);
    const changed = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    const changedResponse = await changed;
    assert.equal(changedResponse.status(), 204);
    assert.deepEqual(Object.keys(changedResponse.request().postDataJSON()).sort(), ['expected_revision', 'reason', 'status']);
    assert.equal(typeof changedResponse.request().postDataJSON().expected_revision, 'string');
    await moderator.getByText('Status change confirmed. Current account state loaded.', { exact: true }).waitFor();
    assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'suspended');
    assert.equal((await api(ordinary, '/api/v1/users/me')).status, 401, 'Suspension left an old normal session usable');
    dialog = await confirmForm(moderator, 'Reactivate', 'totp', harness, actors.moderator.fixture);
    const restored = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason, 'reactivate');
    assert.equal((await restored).status(), 204);
    await moderator.getByText('Status change confirmed. Current account state loaded.', { exact: true }).waitFor();
    assert.equal((await api(ordinary, '/api/v1/users/me')).status, 401, 'Reactivation resurrected an old normal session');
    evidence.checks.push('native modal keyboard loop/Escape return, no pre-verification reason, real UV and TOTP, revision conflict, suspension cuts off a live session and reactivation never restores it');

    checkpoint = 'admin-uncertain';
    const lostPatches = observeStatusPatches(cdp, harness.origin);
    let committed = 0;
    let interceptionFailed = false;
    const interceptions = [];
    const loseResponse = (event) => {
      interceptions.push((async () => {
        try {
          if (event.request.method !== 'PATCH') {
            await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
            return;
          }
          let body = '';
          if (event.responseStatusCode === 401) {
            const result = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
            assert(result.body.length <= 8192, 'Oversized intercepted nonce response');
            body = result.base64Encoded ? Buffer.from(result.body, 'base64').toString('utf8') : result.body;
          }
          lostPatches.response(event, body);
          if (event.responseStatusCode === 204) {
            committed++;
            await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
          } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
        } catch {
          interceptionFailed = true;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }).catch(() => {});
        }
      })());
    };
    cdp.on('Fetch.requestPaused', loseResponse);
    let reconciled = false;
    try {
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `${harness.origin}/api/v1/admin/users/*/status*`, requestStage: 'Response' }] });
      dialog = await confirmForm(moderator, 'Ban');
      await finalSubmit(dialog, markers.reason, 'ban');
      await moderator.getByText(/Outcome unconfirmed; the action was not retried/).waitFor();
      await Promise.all(interceptions);
      assert.equal(interceptionFailed, false, 'Native response interception failed');
      assert.equal(committed, 1);
      lostPatches.assertLostResponse();
      assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'banned');
      assert.equal(await moderator.getByRole('heading', { name: target.user_id, exact: true }).count(), 0);
      lostPatches.reconcile();
      const reread = operationResponse(moderator, `/api/v1/admin/users/${target.user_id}`, 'GET');
      await moderator.getByRole('button', { name: 'Read current state', exact: true }).click();
      assert.equal((await reread).status(), 200);
      await moderator.getByRole('heading', { name: target.user_id, exact: true }).waitFor();
      assert(await moderator.getByText(/matching status proves only current state/).isVisible());
      await Promise.all(interceptions);
      evidence.uncertainMutation = lostPatches.assertLostResponse();
      reconciled = true;
    } finally {
      try {
        await cdp.send('Fetch.disable');
        await Promise.all(interceptions);
        if (reconciled) {
          assert.equal(interceptionFailed, false, 'Native response interception failed during reconciliation');
          evidence.uncertainMutation = lostPatches.assertLostResponse();
        }
      } finally {
        cdp.off('Fetch.requestPaused', loseResponse);
        lostPatches.close();
      }
    }
    evidence.checks.push('every outgoing status PATCH is observed through lost-204 reconciliation, including failed attempts; only the initial exact pre-handler nonce retry is permissible');

    checkpoint = 'admin-protected';
    const combined = actors.combined.page;
    for (const account of [pending, deleting, actors.combined.fixture]) {
      await open(combined, harness, `/admin/users/${account.user_id}`);
      const button = combined.getByRole('button', { name: 'Suspend', exact: true });
      await button.waitFor();
      assert(await button.isDisabled());
    }
    await open(combined, harness, `/admin/users/${actors.dpo.fixture.user_id}`);
    dialog = await confirmForm(combined);
    const protectedResponse = operationResponse(combined, `/api/v1/admin/users/${actors.dpo.fixture.user_id}/status`, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    assert.equal((await protectedResponse).status(), 403);
    await combined.getByText('The status change was not permitted. No change was confirmed.', { exact: true }).waitFor();
    assert.equal((await api(combined, '/api/v1/users/me')).status, 200);
    evidence.checks.push('known self/deleting/unverified targets are disabled; privileged targets stay generic server-side denials');

    // Keep production actor/subnet limits intact. Separate the dense independent
    // scenarios by a real rate window and prove that idle views do not poll.
    checkpoint = 'admin-idle';
    const idleRequests = harness.originEvidence.admin;
    await new Promise((resolve) => setTimeout(resolve, 61_000));
    assert.equal(harness.originEvidence.admin, idleRequests, 'Idle admin views polled the API');
    evidence.checks.push('a full real rate-limit window passes with no background admin requests');

    checkpoint = 'admin-background';
    const unsentPatches = observeStatusPatches(actors.combined.authenticator.cdp, harness.origin);
    try {
      await open(combined, harness, `/admin/users/${actors.ordinary.fixture.user_id}`);
      await combined.getByRole('button', { name: 'Suspend', exact: true }).click();
      dialog = combined.getByTestId('stepup-dialog');
      await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
      await dialog.getByRole('button', { name: 'Use authenticator code', exact: true }).click();
      await dialog.getByLabel('Authenticator code', { exact: true }).fill('123');
      const resume = await hidePortal(combined, actors.combined.context, evidence, 'admin-ready');
      await resume();
      await combined.getByTestId('admin-ready').waitFor();
      await dialog.getByText(/Your pending action was restored/).waitFor();
      await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
      assert.equal(await dialog.getByLabel('Authenticator code', { exact: true }).inputValue(), '');
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      dialog = await confirmForm(combined);
      const backgroundReason = await dialog.getByLabel('Moderation reason', { exact: true }).elementHandle();
      await backgroundReason.fill(markers.backgroundDraft);
      await assertAdminPrivacy(combined, actors.combined.observed, markers);
      const returnToPage = await hidePortal(combined, actors.combined.context, evidence, 'admin-ready');
      await returnToPage();
      await combined.getByTestId('admin-ready').waitFor();
      assert.equal(await combined.getByTestId('stepup-dialog').count(), 0);
      assert(await backgroundReason.evaluate((element) => element.value === ''), 'Backgrounded reason remained on the detached input');
      await backgroundReason.dispose();
      assert.equal(unsentPatches.count, 0, 'Waiting TOTP or backgrounding transmitted a status PATCH');
      evidence.checks.push('real-API hidden/resume rechecks session, capabilities and target; only waiting TOTP intent resumes, never a code/reason/grant or unsent mutation');

      checkpoint = 'admin-grant-expiry';
      dialog = await confirmForm(combined);
      const expiredReason = await dialog.getByLabel('Moderation reason', { exact: true }).elementHandle();
      await expiredReason.fill(markers.expiredDraft);
      await combined.getByRole('alert').filter({ hasText: /Verification expired/ }).waitFor({ timeout: 30_000 });
      assert.equal(await combined.getByTestId('stepup-dialog').count(), 0);
      assert(await expiredReason.evaluate((element) => element.value === ''), 'Expired reason remained on the detached input');
      await expiredReason.dispose();
      assert.equal(unsentPatches.count, 0, 'Pre-send grant expiry transmitted a status PATCH');
      await assertAdminPrivacy(combined, actors.combined.observed, markers);
      evidence.checks.push('real short-lived grant expiry clears the detached final-reason input with zero outgoing status PATCHes');
    } finally { unsentPatches.close(); }

    checkpoint = 'admin-revocation';
    dialog = await confirmForm(combined);
    harness.fixture('admin-revoke', { user_id: actors.combined.fixture.user_id, role: 'moderator' });
    const revoked = operationResponse(combined, `/api/v1/admin/users/${actors.ordinary.fixture.user_id}/status`, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    assert.equal((await revoked).status(), 403);
    await combined.getByTestId('admin-ready').waitFor({ state: 'hidden' });
    assert.equal(await combined.getByLabel('Moderation reason', { exact: true }).count(), 0);
    assert.equal((await api(combined, '/api/v1/users/me')).status, 200);
    evidence.checks.push('permission revocation after grant clears private state without logging out the normal session');

    checkpoint = 'admin-audit';
    await open(dpo, harness, '/admin/audit-logs');
    await dpo.getByLabel('Event type (exact)', { exact: true }).fill(audit.event_type);
    await dpo.getByLabel('Page size', { exact: true }).fill('20');
    const logs = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: 'Search audit logs', exact: true }).click();
    const logsResponse = await logs;
    const logBody = await logsResponse.json();
    const logText = JSON.stringify(logBody);
    assert(Buffer.byteLength(logText) > 256 * 1024 && Buffer.byteLength(logText) < 4 * 1024 * 1024);
    assert(logText.includes(markers.auditPayload), 'Signed audit response did not carry the controlled payload marker');
    assert(logBody.items.every((row) => typeof row.seq === 'string'));
    assert(logBody.items.some((row) => BigInt(row.seq) > BigInt(Number.MAX_SAFE_INTEGER)));
    const initialQuery = new URL(logsResponse.url()).searchParams;
    assert(initialQuery.get('start_time').endsWith('Z') && initialQuery.get('end_time').endsWith('Z'));
    await dpo.getByRole('button', { name: /^View details for sequence / }).first().click();
    const details = dpo.getByRole('dialog', { name: 'Audit record details', exact: true });
    await details.waitFor();
    assert((await details.textContent()).includes(markers.auditPayload), 'Audit details did not render the controlled payload as text');
    assert.equal(await details.locator('img, script, iframe, a[href]').count(), 0);
    assert.equal(await dpo.evaluate(() => Boolean(globalThis.__adminPayloadExecuted)), false);
    await assertAdminPrivacy(dpo, actors.dpo.observed, markers);
    await dpo.keyboard.press('Escape');
    await dpo.getByLabel('Page size', { exact: true }).fill('2');
    const firstPage = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: 'Search audit logs', exact: true }).click();
    const firstResponse = await firstPage;
    const first = await firstResponse.json();
    assert(first.has_more && typeof first.next_before_seq === 'string');
    const older = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: 'Older records', exact: true }).click();
    const olderResponse = await older;
    const olderQuery = new URL(olderResponse.url()).searchParams;
    assert.equal(olderQuery.get('before_seq'), first.next_before_seq);
    for (const key of ['start_time', 'end_time', 'event_type', 'limit'])
      assert.equal(olderQuery.get(key), new URL(firstResponse.url()).searchParams.get(key));
    assert((await olderResponse.json()).items.every((row) => BigInt(row.seq) < BigInt(first.next_before_seq)));
    await layout(dpo, 'audit', evidence, artifactDirectory);
    evidence.checks.push('real signed audit list exceeds 256KiB within its 4MiB budget, exact high-int64 keyset pages, UTC frozen filters, inert payload dialog');

    checkpoint = 'admin-read-failures';
    for (const failure of [
      { status: 429, headers: { 'Retry-After': '2' }, body: '{"error":"rate_limit_exceeded"}' },
      { status: 503, body: '{"error":"audit_unavailable"}' },
      { status: 200, body: '{"items":' },
      { status: 200, body: JSON.stringify({ padding: 'x'.repeat(4 * 1024 * 1024) }) },
    ]) {
      await queryFault(dpo, '/api/v1/admin/audit-logs', () => dpo.getByRole('button', { name: 'Search audit logs', exact: true }).click(), failure);
      assert.equal(await dpo.getByRole('button', { name: /^View details for sequence / }).count(), 0);
    }
    // A real outbox failure, not a fulfilled fake response, must withhold data.
    harness.fixture('admin-audit-failure', { scenario: 'on' });
    try {
      await visit(support, harness.origin, '/admin/users');
      await support.getByRole('main').getByRole('alert').waitFor({ state: 'visible' });
      assert.equal(await support.getByTestId('admin-ready').count(), 0);
      assert.equal(await support.locator('table').count(), 0);
    } finally { harness.fixture('admin-audit-failure', { scenario: 'off' }); }
    evidence.checks.push('malformed/oversized/429/503 responses clear results without retry; real failed durable audit withholds the entire private surface');

    checkpoint = 'admin-integrity';
    await open(dpo, harness, '/admin/integrity');
    const firstProof = operationResponse(dpo, '/api/v1/admin/audit-logs/verify', 'GET');
    await dpo.getByRole('button', { name: 'Start new run', exact: true }).click();
    const initial = await (await firstProof).json();
    assert.equal(initial.canonical_version, 2, 'Verifier must declare its canonical format');
    assert.equal(initial.verified, true, 'Untampered fixture chain must verify');
    assert.equal(initial.complete, false, 'The bounded first page must remain partial');
    assert.equal(initial.after_seq, '0');
    assert.equal(typeof initial.through_seq, 'string');
    assert.equal(initial.scope, 'stored_segment_relative_to_seed; not complete ingestion, tail-truncation detection, or independent historical authenticity');
    harness.fixture('admin-audit', { user_id: target.user_id });
    const continuation = operationResponse(dpo, '/api/v1/admin/audit-logs/verify', 'GET');
    await dpo.getByRole('button', { name: 'Continue verification', exact: true }).click();
    const continuedResponse = await continuation;
    const continuedQuery = new URL(continuedResponse.url()).searchParams;
    assert.equal(continuedQuery.get('through_seq'), initial.through_seq);
    assert.equal(continuedQuery.get('after_seq'), initial.next_after_seq);
    assert.equal(continuedQuery.get('predecessor_hash'), initial.last_hash);
    await dpo.getByRole('button', { name: 'Stop verification', exact: true }).click();
    await dpo.getByText(/No complete-run conclusion was reached/).waitFor();
    await layout(dpo, 'integrity', evidence, artifactDirectory);
    const verifier = actors.super_admin.page;
    await open(verifier, harness, '/admin/integrity');
    assert.equal((await api(verifier, '/api/v1/admin/users')).status, 403);
    assert.equal((await api(verifier, '/api/v1/admin/audit-logs')).status, 403);
    await verifier.getByLabel('Chain', { exact: true }).selectOption('ledger');
    const ledgerProof = operationResponse(verifier, '/api/v1/admin/ledger/verify', 'GET');
    await verifier.getByRole('button', { name: 'Start new run', exact: true }).click();
    assert.equal((await (await ledgerProof).json()).chain, 'ledger');
    evidence.checks.push('independent explicit verifier pages use fixed captured bounds and prior hashes across later appends; stop stays partial; verifier-only role cannot read accounts/payloads');

    checkpoint = 'admin-clearing';
    const back = await hidePortal(dpo, actors.dpo.context, evidence, 'admin-ready');
    await back();
    await dpo.getByTestId('admin-ready').waitFor();
    assert.equal(await dpo.getByTestId('verification-page').count(), 0);
    await visit(dpo, harness.origin, '/login');
    await dpo.goBack({ waitUntil: 'load' });
    await dpo.getByTestId('admin-ready').waitFor();
    evidence.nativeBfcacheRestoreObserved ||= await dpo.evaluate(() => globalThis.__portalPageShows.includes(true));
    assert.equal(await dpo.getByTestId('verification-page').count(), 0);
    const supportProfile = await api(support, '/api/v1/users/me');
    harness.fixture('expire-session', { user_id: actors.support.fixture.user_id, session_id: supportProfile.body.session.id });
    await visit(support, harness.origin, `/admin/users/${target.user_id}`);
    // Next.js also exposes a route-announcement alert in a shadow root. Scope
    // this assertion to the application's session feedback.
    await support.getByRole('main').getByRole('alert').filter({
      hasText: 'Your session is no longer available. Sign in again to continue.',
    }).waitFor();
    assert.equal(await support.getByTestId('admin-ready').count(), 0);
    assert.equal(await support.getByRole('link', { name: 'Sign in with a passkey', exact: true }).getAttribute('href'), '/login?returnTo=%2Fadmin%2Fusers');
    evidence.checks.push('background/history discard proof progress; real session expiry clears private data and strips detail identifiers from login returnTo');

    await open(moderator, harness, detailPath);
    const sibling = await actors.moderator.context.newPage();
    await visit(sibling, harness.origin, '/dashboard');
    await sibling.getByTestId('portal-ready').waitFor();
    await sibling.getByRole('button', { name: 'Sign out', exact: true }).click();
    await sibling.waitForURL(harness.origin + '/login');
    await moderator.bringToFront();
    await moderator.getByTestId('admin-ready').waitFor({ state: 'hidden' });
    assert.equal(await moderator.getByRole('heading', { name: target.user_id, exact: true }).count(), 0);
    await sibling.close();
    evidence.checks.push('real cross-tab logout removes the admin view and broadcasts only the neutral invalidation marker');

    checkpoint = 'admin-ledger-states';
    await harness.waitForAdminDelivery();
    harness.fixture('admin-tamper', { scenario: 'ledger-payload-absent' });
    await open(dpo, harness, '/admin/integrity');
    await dpo.getByLabel('Chain', { exact: true }).selectOption('ledger');
    const tampered = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: 'Start new run', exact: true }).click();
    const broken = await (await tampered).json();
    assert.equal(broken.verified, false);
    assert.equal(broken.failure_reason, 'payload_absent_without_erasure_record');
    await dpo.getByRole('main').getByRole('alert').waitFor();
    assert(await dpo.getByRole('button', { name: 'Continue verification', exact: true }).isDisabled());
    harness.fixture('admin-chain-state', { scenario: 'erased' });
    let allErased = 0;
    for (let page = 0; page < 32; page++) {
      const nextProof = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
      await dpo.getByRole('button', { name: page === 0 ? 'Start new run' : 'Continue verification', exact: true }).click();
      const result = await (await nextProof).json();
      assert(result.verified && result.checked > 0 && result.checked === result.erased_checked);
      allErased += result.checked;
      if (result.complete) break;
      assert(page < 31, 'Fixture proof exceeded its bounded page budget');
    }
    assert(allErased > 0);
    await dpo.getByText(/without verifying its erased content/).waitFor();
    harness.fixture('admin-chain-state', { scenario: 'empty' });
    const empty = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: 'Start new run', exact: true }).click();
    const emptyBody = await (await empty).json();
    assert(emptyBody.verified && emptyBody.complete && emptyBody.checked === 0);
    await dpo.getByText('No records checked.', { exact: true }).waitFor();
    await dpo.getByText(/not proof that no activity occurred/).waitFor();
    harness.fixture('admin-chain-state', { scenario: 'missing-head' });
    const missing = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: 'Start new run', exact: true }).click();
    assert.equal((await missing).status(), 400);
    await dpo.getByRole('main').getByRole('alert').waitFor();
    assert(await dpo.getByRole('button', { name: 'Continue verification', exact: true }).isDisabled());
    evidence.checks.push('real tampered ledger stops; database-relative authorized erasure never claims content verification; initialized empty and missing head stay distinct');

    checkpoint = 'admin-final';
    for (const { page, observed } of Object.values(actors)) {
      await assertAdminPrivacy(page, observed, markers);
      assert.equal(observed.downloads, 0);
    }
    assert(harness.originEvidence.admin > 0 && harness.originEvidence.unsafe > 0);
    assert.equal(harness.originEvidence.mismatched, 0);
    assert.equal(harness.originEvidence.referrers, 0);
    harness.assertHealthy();
    evidence.checks.push('fresh queryless-htu DPoP proofs, strict cookies/CSP, exact unsafe Origin; controlled reason/draft/payload markers absent from console, URLs, headers, telemetry bodies, history and persistent private state');
    evidence.checks.push('headless light/dark 44px pointer targets including checkbox labels, text/focus contrast, modal/table keyboard traversal and 320x256 zoom-equivalent reflow; not native zoom or assistive-technology certification');
    evidence.manualGates = [
      'Physical platform authenticators, browser zoom, and assistive-technology review',
      'DPO/Legal-approved production policy, ingress/logging review, threat-model review and downstream v1/v2 rollout',
      ...(!evidence.nativeHiddenTabObserved ? ['Native hidden-tab transition not observed; complete visibility events were injected against real API'] : []),
      ...(!evidence.nativeBfcacheRestoreObserved ? ['Native bfcache restore not observed; history/pagehide cleanup was tested'] : []),
    ];
    return evidence;
  } finally {
    const closed = await Promise.allSettled(contexts.map((context) => context.close()));
    const browserClosed = await browser.close().then(() => true, () => false);
    assert(browserClosed && closed.every((result) => result.status === 'fulfilled'), 'Admin browser resources did not all close');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const evidence = await runAdminBrowser();
    console.log(JSON.stringify(evidence, null, 2));
    console.log('Focused real-API admin browser checks and teardown passed');
  } catch (error) {
    console.error(browserFailure(error, checkpoint));
    process.exitCode = 1;
  }
}
