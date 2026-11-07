import { assertOnlyPreferenceCookies, browserLocale, browserLocales, configureBrowserPreferences, exercisePreferenceSwitch, localizedText, screenshotName, setBrowserLocale, waitForFonts } from './browser-localization.mjs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, readlink, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { browserFailure, guardBrowserFailures, legalCoordinateRequest, legalIdempotencyKey, legalReferenceRequest, portalRoute, startPortalHarness } from './portal-harness.mjs';
import {
  addAuthenticator, api, clean, hidePortal, newContext, operationResponse as waitForOperation, signIn, visit,
} from './web-portal.browser.mjs';

let checkpoint = 'startup';
const routes = ['/admin', '/admin/users', '/admin/audit-logs', '/admin/integrity', '/admin/legal'];
const script = fileURLToPath(import.meta.url);
const workspace = resolve(dirname(script), '../..');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const statusRoute = /^\/api\/v1\/admin\/users\/[^/]+\/status\/?$/;
const legalCreate = ['/api/v1/admin/legal-holds', '/api/v1/admin/preservation-requests'];
const legalLookup = '/api/v1/admin/legal-inquiry/lookup';
const legalRelease = /^\/api\/v1\/admin\/legal-holds\/[0-9a-f-]{36}$/;

export function observeLegalWrites(cdp, origin) {
  const attempts = [];
  let reconciliation = false;
  let invalid = false;
  const outgoing = ({ requestId, request }) => {
    try {
      const url = new URL(request.url);
      const createCandidate = request.method === 'POST' && legalCreate.some((path) => url.pathname === path || url.pathname === path + '/');
      const releaseCandidate = request.method === 'DELETE' && /^\/api\/v1\/admin\/legal-holds\/[^/]+\/?$/.test(url.pathname);
      if (!createCandidate && !releaseCandidate) return;
      const headers = new Headers(request.headers);
      const claims = JSON.parse(Buffer.from((headers.get('DPoP') || '').split('.')[1], 'base64url').toString());
      assert(url.origin === origin && !url.search && !url.hash && typeof requestId === 'string');
      const key = headers.get('Idempotency-Key');
      if (request.method === 'POST') {
        legalIdempotencyKey(url.pathname, request.method, key);
        assert(typeof request.postData === 'string');
      } else assert(legalRelease.test(url.pathname) && key === null && !request.postData);
      assert(claims.nonce === undefined || typeof claims.nonce === 'string');
      attempts.push({
        id: requestId, reconciliation, status: null, challenge: null,
        followsChallenge: attempts.length === 1 && attempts[0].status === 401 && attempts[0].challenge !== null,
        nonce: claims.nonce === undefined ? null : digest(claims.nonce),
        logicalRequest: digest(JSON.stringify([request.method, request.url, request.postData || '', key,
          headers.get('X-Portal-Session'), headers.get('X-Step-Up-Auth')])),
      });
    } catch { invalid = true; }
  };
  cdp.on('Network.requestWillBeSent', outgoing);
  return {
    get count() { assert(!invalid, 'Legal write observation failed'); return attempts.length; },
    response(event, body = '') {
      const attempt = attempts.find(({ id }) => id === event.networkId);
      assert(attempt && attempt.status === null, 'Unmatched or repeated legal write response');
      attempt.status = event.responseStatusCode;
      const headers = new Headers();
      for (const { name, value } of event.responseHeaders || []) headers.append(name, value);
      const nonce = headers.get('DPoP-Nonce');
      if (attempt.status === 401 && nonce && /^[A-Za-z0-9._~-]{1,1024}$/.test(nonce) &&
          /^DPoP[ \t]+error="use_dpop_nonce"$/i.test(headers.get('WWW-Authenticate') || '')) {
        assert(Buffer.byteLength(body) <= 4096, 'Oversized legal nonce challenge');
        if (JSON.parse(body)?.error === 'use_dpop_nonce') attempt.challenge = digest(nonce);
      }
    },
    reconcile() { reconciliation = true; },
    assertLostResponse(status) {
      assert(!invalid && [201, 204].includes(status), 'Invalid lost legal write observation');
      assert(attempts.length === 1 || attempts.length === 2, 'Unexpected outgoing legal write, including a failed replay');
      assert(attempts.every((attempt) => !attempt.reconciliation), 'Legal state reconciliation transmitted a write');
      if (attempts.length === 2) {
        const [first, retry] = attempts;
        assert(first.status === 401 && first.challenge && first.nonce === null && retry.followsChallenge &&
          retry.nonce === first.challenge && retry.logicalRequest === first.logicalRequest,
        'Legal nonce retry changed the body, key, scope or grant');
      }
      assert(attempts.at(-1).status === status && !attempts.at(-1).challenge, 'Expected one deliberately lost real legal success');
      return { outgoingLegalWrites: attempts.length, preHandlerNonceRetries: attempts.length - 1, reconciliationWrites: 0 };
    },
    close() { cdp.off('Network.requestWillBeSent', outgoing); attempts.length = 0; },
  };
}

export function observeLegalPrivacy(context, harness, markers, failures) {
  harness.secrets.push(...Object.values(markers));
  for (const value of Object.values(markers)) harness.legalSecrets.add(value);
  context.on('request', (request) => {
    try {
      const url = new URL(request.url());
      const headers = new Headers(request.headers());
      const contains = (text) => [...harness.legalSecrets].some((value) => value &&
        (text.includes(value) || text.includes(encodeURIComponent(value)) || text.includes(JSON.stringify(value).slice(1, -1))));
      for (const value of harness.legalSecrets) {
        if (value && (url.href.includes(value) || url.href.includes(encodeURIComponent(value)))) {
          // Existing Task 7.5 independently reads the same ledger coordinates.
          // This is not a legal-result navigation or a new arbitrary query rule.
          const existingReference = harness.routeReferences?.has(value) && url.origin === harness.origin &&
            portalRoute(url.pathname).includes('{id}') && !url.search && !url.hash;
          assert(legalReferenceRequest(request, value, harness) || legalCoordinateRequest(request, value, harness) || existingReference);
        }
      }
      if (url.origin === harness.origin && url.pathname.startsWith('/api/')) {
        const legalGrant = headers.get('x-step-up-auth');
        if (legalGrant) assert(!url.search && !url.hash && (
          (request.method() === 'POST' && [...legalCreate, legalLookup].includes(url.pathname)) ||
          (request.method() === 'DELETE' && legalRelease.test(url.pathname)) ||
          (request.method() === 'PATCH' && statusRoute.test(url.pathname))
        ), 'A step-up grant escaped a required admin operation');
        for (const name of ['dpop', 'x-step-up-auth']) {
          const value = headers.get(name);
          if (value) { harness.secrets.push(value); harness.legalSecrets.add(value); }
        }
        for (const name of ['cookie', 'dpop', 'x-portal-session', 'x-step-up-auth']) headers.delete(name);
        const key = headers.get('Idempotency-Key');
        if (key !== null) {
          legalIdempotencyKey(url.pathname + url.search + url.hash, request.method(), key);
          harness.secrets.push(key);
          harness.legalSecrets.add(key);
          headers.delete('Idempotency-Key');
        }
      }
      assert(!contains(JSON.stringify([...headers])));
      const body = request.postData() || '';
      if (!contains(body)) return;
      assert(url.origin === harness.origin && !url.search && !url.hash && request.method() === 'POST');
      const allowed = legalCreate.includes(url.pathname)
        ? ['account_ref', 'reason', 'requesting_authority', ...(url.pathname.endsWith('/legal-holds') ? ['legal_basis', 'review_at'] : ['expires_at'])]
        : url.pathname === legalLookup ? ['identifier', 'requesting_authority', 'case_reference', 'purpose', 'cursor'] : [];
      assert(allowed.length > 0);
      const rest = JSON.parse(body);
      for (const key of allowed) delete rest[key];
      assert(!contains(JSON.stringify(rest)));
      assert(!Object.entries(markers).some(([key, value]) => key.endsWith('Draft') && body.includes(value)),
        'An unsent legal draft was transmitted');
    } catch { failures.push('Private legal data escaped its exact API request boundary'); }
  });
}

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
  await page.getByRole('button', { name: localizedText(action), exact: true }).click();
  const dialog = page.getByTestId('stepup-dialog');
  await dialog.waitFor({ state: 'visible' });
  assert(await dialog.evaluate((element) => element instanceof HTMLDialogElement && element.open));
  assert.equal(await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).count(), 0);
  await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
  if (method === 'totp') {
    await dialog.getByRole('button', { name: localizedText('Use authenticator code'), exact: true }).click();
    const current = harness.fixture('totp-code', { user_id: fixture.user_id });
    await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(current.code);
    await dialog.getByRole('button', { name: localizedText('Verify code'), exact: true }).click();
  } else {
    await dialog.getByRole('button', { name: localizedText('Verify with a passkey'), exact: true }).click();
  }
  await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).waitFor({ state: 'visible' });
  assert(await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).evaluate((element) => element === document.activeElement));
  return dialog;
}

async function finalSubmit(dialog, reason, action = 'suspend') {
  await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).fill(reason);
  await dialog.getByRole('checkbox', { name: localizedText(/I reviewed the account/) }).check();
  await dialog.getByRole('button', { name: localizedText(`Confirm ${action}`), exact: true }).click();
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
  for (const viewport of [{ width: 1280, height: 900 }, { width: 768, height: 1024 }, { width: 390, height: 844 }, { width: 320, height: 900 }, { width: 320, height: 256 }]) {
    for (const dark of [false, true]) {
      await page.setViewportSize(viewport);
      await page.evaluate((enabled) => document.documentElement.classList.toggle('dark', enabled), dark);
      await waitForFonts(page);
      assert.deepEqual(await page.evaluate(adminAppearance), [], 'Admin pointer targets, contrast or reflow regressed');
      const modal = page.locator('dialog[open]');
      if (await modal.count()) {
        const stops = await modal.locator('a[href], button:enabled, input:enabled, select:enabled, textarea:enabled').count();
        assert(stops > 0, 'Admin modal has no keyboard controls');
        for (let index = 0; index < stops; index++) {
          await page.keyboard.press('Tab');
          const failures = await page.evaluate(adminAppearance, { focusedOnly: true });
          if (failures.length) console.error(JSON.stringify({ check: 'admin-modal-focus', viewport, dark, failures }));
          assert.deepEqual(failures, [], 'Admin modal keyboard focus regressed');
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
          const entryFailures = await page.evaluate(adminAppearance, { focusedOnly: true });
          if (entryFailures.length) console.error(JSON.stringify({ check: 'admin-table-entry-focus', viewport, dark, failures: entryFailures }));
          assert.deepEqual(entryFailures, [], 'Admin table entry focus regressed');
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
          path: resolve(artifactDirectory, screenshotName(name, viewport, dark)),
          fullPage: true,
          animations: 'disabled',
          mask: [page.locator('tbody, main dd, main .font-mono, input, textarea, [data-legal-private], [data-testid="legal-outcome"], [data-testid="legal-coverage"]')],
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

async function validateLegal(harness, actors, evidence, artifactDirectory, markers) {
  const fixture = harness.fixture('admin-legal-seed');
  assert.equal(fixture.canonical_version, 2);
  const { deleted_account_ref: deleted, current_account_ref: current, absent_account_ref: absent } = fixture;
  const dpo = actors.dpo;
  const second = actors.legal_operator;
  const combined = actors.combined;
  const grants = new Set();
  const verificationTimes = new Map();
  let verificationCount = 0;
  const holdsPath = legalCreate[0];
  const preservePath = legalCreate[1];
  const fields = { client_ip: 'Client IP', ip_subnet: 'IP subnet', user_agent: 'User agent',
    device_fingerprint: 'Device fingerprint', client_id: 'Client ID', scope: 'Scope' };
  const hold = { account_ref: deleted, reason: markers.reason, requesting_authority: markers.requesting_authority,
    legal_basis: markers.legal_basis, review_at: '2020-01-01T00:00:00.000Z' };
  const preserve = (account) => ({ account_ref: account, reason: markers.reason,
    requesting_authority: markers.requesting_authority, expires_at: hold.review_at });
  const inquiry = { identifier_type: 'email', identifier: fixture.email, requesting_authority: markers.requesting_authority,
    case_reference: markers.case_reference, purpose: markers.purpose, start_time: fixture.start_time,
    end_time: fixture.end_time, limit: 20, fields: [] };
  const recordedOperation = randomUUID();
  const state = (account, key, kind = 'legal_hold') => harness.fixture('admin-legal-state', {
    account_ref: account, ...(key ? { operation_id: key, request_kind: kind } : {}),
  });
  const response = async (page, path, method, status) => {
    const body = status === 204 ? null : harness.captureJSON(path, method, status);
    const result = await waitForOperation(page, path, method);
    assert.equal(result.status(), status, 'Unexpected legal API outcome');
    const grant = result.request().headers()['x-step-up-auth'];
    if (method !== 'GET') {
      assert(typeof grant === 'string' && !grants.has(digest(grant)), 'A UI legal operation reused a step-up grant');
      grants.add(digest(grant));
    }
    return { response: result, body: body && await body };
  };
  const section = async (actor, name) => {
    if (new URL(actor.page.url()).pathname !== '/admin/legal') await open(actor.page, harness, '/admin/legal');
    else {
      await actor.page.bringToFront();
      await actor.page.getByTestId('admin-ready').waitFor();
    }
    const button = actor.page.getByRole('button', { name: localizedText(name), exact: true });
    await button.click();
    assert.equal(await button.getAttribute('aria-pressed'), 'true');
    assert.equal(new URL(actor.page.url()).search + new URL(actor.page.url()).hash, '');
  };
  const verify = async (actor, button, { method = 'passkey' } = {}) => {
    const times = verificationTimes.get(actor) || [];
    assert(times.length < 20 && verificationCount < 30, 'Legal scenarios exceed the unchanged production step-up budget');
    if (times.length >= 5) {
      const wait = times.at(-5) + 61_000 - Date.now();
      if (wait > 0) {
        const requests = harness.originEvidence.legal;
        await new Promise((resolve) => setTimeout(resolve, wait));
        assert.equal(harness.originEvidence.legal, requests, 'Idle legal views polled or retried during a real rate window');
      }
    }
    const { page } = actor;
    await button.click();
    const dialog = page.getByTestId('stepup-dialog');
    await dialog.waitFor({ state: 'visible' });
    assert.equal(await dialog.getByLabel(localizedText('Reason'), { exact: true }).count(), 0);
    assert.equal(await dialog.getByLabel(localizedText('Email for attribution'), { exact: true }).count(), 0);
    await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
    const captured = harness.captureJSON('/api/v1/auth/stepup/verify', 'POST', 200);
    times.push(Date.now());
    verificationTimes.set(actor, times);
    verificationCount++;
    if (method === 'totp') {
      await dialog.getByRole('button', { name: localizedText('Use authenticator code'), exact: true }).click();
      await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(harness.fixture('totp-code', { user_id: actor.fixture.user_id }).code);
      await dialog.getByRole('button', { name: localizedText('Verify code'), exact: true }).click();
    } else await dialog.getByRole('button', { name: localizedText('Verify with a passkey'), exact: true }).click();
    const grant = await captured;
    assert(typeof grant.token === 'string' && grant.token.length > 0, 'Missing real verification grant');
    harness.secrets.push(grant.token);
    harness.legalSecrets.add(grant.token);
    await dialog.locator('[data-legal-private]').waitFor({ state: 'visible' });
    return { dialog, token: grant.token };
  };
  const fillCreate = async (dialog, payload, key, pinned = false) => {
    const target = dialog.getByLabel(localizedText('Original account reference'), { exact: true });
    if (pinned) {
      assert.equal(await target.inputValue(), payload.account_ref);
      assert(await target.isDisabled(), 'Selected attribution reference was not pinned');
    } else await target.fill(payload.account_ref);
    const operation = dialog.getByLabel(localizedText('Operation UUID'), { exact: true });
    assert.equal(await operation.inputValue(), '', 'A legal operation UUID was generated or recovered in the browser');
    await operation.fill(key);
    await dialog.getByLabel(localizedText('Reason'), { exact: true }).fill(`  ${payload.reason}  `);
    await dialog.getByLabel(localizedText('Requesting authority'), { exact: true }).fill(payload.requesting_authority);
    if ('legal_basis' in payload) await dialog.getByLabel(localizedText('Legal basis'), { exact: true }).fill(payload.legal_basis);
    await dialog.getByLabel(localizedText('legal_basis' in payload ? 'Review at (UTC)' : 'Expires at (UTC)'), { exact: true })
      .fill(payload.review_at || payload.expires_at || '');
    const detached = await dialog.locator('input:not([type=checkbox]), textarea').elementHandles();
    try {
      await dialog.getByRole('button', { name: localizedText('Review request'), exact: true }).click();
      assert.equal(await dialog.getByLabel(localizedText('Reason'), { exact: true }).count(), 0);
      assert((await Promise.all(detached.map((control) => control.evaluate((element) =>
        element.value === '' && element.defaultValue === '' &&
        (element instanceof HTMLTextAreaElement ? element.textContent === '' : !element.getAttribute('value')))))).every(Boolean),
      'Reviewing legal inputs retained a detached live or default value');
    } finally { await Promise.all(detached.map((control) => control.dispose())); }
  };
  const confirm = async (dialog, label, double = false) => {
    await dialog.getByRole('checkbox', { name: localizedText(/^I reviewed /) }).check();
    const button = dialog.getByRole('button', { name: localizedText(label), exact: true });
    if (double) await button.evaluate((element) => { element.click(); element.click(); });
    else await button.click();
  };
  const create = async (actor, payload, key, { replay = false, method, pinned = false, double = false, status = replay ? 200 : 201 } = {}) => {
    const kind = 'legal_basis' in payload ? 'hold' : 'preservation';
    if (!pinned) await section(actor, kind === 'hold' ? 'Legal Holds' : 'Preservation');
    const { dialog } = await verify(actor, actor.page.getByRole('button', {
      name: localizedText(kind === 'hold' ? 'Apply Legal Hold' : 'Record preservation'), exact: true,
    }), { method });
    await fillCreate(dialog, payload, key, pinned);
    const received = response(actor.page, kind === 'hold' ? holdsPath : preservePath, 'POST', status);
    await confirm(dialog, kind === 'hold' ? 'Confirm Legal Hold' : 'Confirm preservation', double);
    const result = await received;
    assert.equal(result.response.request().headers()['idempotency-key'], key);
    assert.deepEqual(result.response.request().postDataJSON(), payload, 'Legal create changed the recorded normalized tuple');
    if (status < 300) {
      const outcome = actor.page.getByTestId('legal-outcome');
      await outcome.waitFor({ state: 'visible' });
      assert.equal(await outcome.getAttribute('data-outcome'), replay ? 'replayed' : 'confirmed');
      assert.equal(result.body.replayed, replay);
    }
    return result.body;
  };
  const readHolds = async (actor, account, limit = 20) => {
    await section(actor, 'Legal Holds');
    const form = actor.page.getByRole('form', { name: localizedText('Read Legal Holds'), exact: true });
    if (account === undefined) await form.getByRole('checkbox', { name: localizedText('All original references'), exact: true }).check();
    else {
      await form.getByRole('checkbox', { name: localizedText('All original references'), exact: true }).uncheck();
      await form.getByLabel(localizedText('Original account reference'), { exact: true }).fill(account);
    }
    await form.getByLabel(localizedText('Hold status'), { exact: true }).selectOption('all');
    await form.getByLabel(localizedText('Page size'), { exact: true }).fill(String(limit));
    const received = response(actor.page, holdsPath, 'GET', 200);
    await form.getByRole('button', { name: localizedText('Read Legal Holds'), exact: true }).click();
    const result = await received;
    assert.equal(new URL(result.response.url()).searchParams.get('account_ref'), account ?? null);
    if (result.body.items.length) await actor.page.getByTestId('legal-hold-row').first().waitFor();
    return result.body;
  };
  const prepareRelease = async (actor, account, id) => {
    await readHolds(actor, account);
    const row = actor.page.getByTestId('legal-hold-row').filter({ hasText: localizedText(id) });
    const { dialog } = await verify(actor, row.getByRole('button', { name: localizedText('Release request'), exact: true }));
    assert((await dialog.textContent()).includes(id), 'Release did not pin the immutable request UUID');
    assert.equal(await dialog.getByLabel(localizedText('Reason'), { exact: true }).count(), 0);
    return dialog;
  };
  const release = async (actor, account, id, status = 204) => {
    const dialog = await prepareRelease(actor, account, id);
    const received = response(actor.page, `${holdsPath}/${id}`, 'DELETE', status);
    await confirm(dialog, 'Confirm release');
    const result = await received;
    assert(!result.response.request().postData() && !result.response.request().headers()['idempotency-key']);
    if (status === 204) await actor.page.getByTestId('legal-outcome').waitFor();
    return result;
  };
  const prepareLookup = async (actor, query = inquiry) => {
    await section(actor, 'Attribution');
    const verified = await verify(actor, actor.page.getByRole('button', { name: localizedText('Start attribution inquiry'), exact: true }));
    for (const [key, label] of Object.entries(fields)) {
      const checkbox = verified.dialog.getByRole('checkbox', { name: localizedText(label), exact: true });
      assert(!(await checkbox.isChecked()), 'Disclosure opt-in was restored or enabled by default');
      if (query.fields.includes(key)) await checkbox.check();
    }
    for (const [key, label] of [['identifier', 'Email for attribution'], ['requesting_authority', 'Requesting authority'],
      ['case_reference', 'Case reference'], ['purpose', 'Inquiry purpose'], ['start_time', 'Start time (UTC)'], ['end_time', 'End time (UTC)'], ['limit', 'Page size']])
      await verified.dialog.getByLabel(localizedText(label), { exact: true }).fill(String(query[key]));
    await verified.dialog.getByRole('button', { name: localizedText('Review request'), exact: true }).click();
    return verified;
  };
  const lookup = async (actor, query = inquiry, status = 200) => {
    const { dialog } = await prepareLookup(actor, query);
    const received = response(actor.page, legalLookup, 'POST', status);
    await confirm(dialog, 'Confirm lookup');
    const result = await received;
    const submitted = result.response.request().postDataJSON();
    assert.deepEqual({ ...submitted, fields: [...submitted.fields].sort() }, { ...query, fields: [...query.fields].sort() });
    if (status === 200) await actor.page.getByTestId('legal-coverage').waitFor();
    return result;
  };
  const lostWrite = async (actor, path, status, send, reconcile) => {
    const cdp = actor.authenticator.cdp;
    const observer = observeLegalWrites(cdp, harness.origin);
    const pending = [];
    let failed = false;
    let committed = 0;
    const paused = (event) => pending.push((async () => {
      try {
        if (!['POST', 'DELETE'].includes(event.request.method)) {
          await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
          return;
        }
        let body = '';
        if (event.responseStatusCode === 401) {
          const result = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
          assert(result.body.length <= 8192);
          body = result.base64Encoded ? Buffer.from(result.body, 'base64').toString('utf8') : result.body;
        }
        observer.response(event, body);
        if (event.responseStatusCode === status) {
          committed++;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
      } catch {
        failed = true;
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }).catch(() => {});
      }
    })());
    cdp.on('Fetch.requestPaused', paused);
    try {
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: harness.origin + path, requestStage: 'Response' }] });
      await send();
      await actor.page.getByTestId('legal-outcome').waitFor();
      assert.equal(await actor.page.getByTestId('legal-outcome').getAttribute('data-outcome'), 'unconfirmed');
      await Promise.all(pending);
      assert(!failed && committed === 1, 'Lost legal response interception did not capture one real committed success');
      observer.assertLostResponse(status);
      observer.reconcile();
      await reconcile();
      await Promise.all(pending);
      assert(!failed && committed === 1);
      return observer.assertLostResponse(status);
    } finally {
      try { await cdp.send('Fetch.disable'); await Promise.all(pending); }
      finally { cdp.off('Fetch.requestPaused', paused); observer.close(); }
    }
  };

  checkpoint = 'legal-access';
  for (const role of ['support', 'moderator', 'super_admin']) {
    const actor = actors[role];
    await open(actor.page, harness, '/admin/legal');
    await actor.page.getByRole('main').getByRole('alert').filter({ hasText: localizedText(/No legal operation/) }).waitFor();
    assert.equal(await actor.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }).count(), 0);
    const sessionID = (await api(actor.page, '/api/v1/users/me')).body.session.id;
    for (const [path, options] of [
      [holdsPath, {}], [holdsPath, { method: 'POST', body: hold, idempotencyKey: recordedOperation }],
      [preservePath, { method: 'POST', body: preserve(deleted), idempotencyKey: recordedOperation }],
      [legalLookup, { method: 'POST', body: inquiry }],
    ]) assert.equal((await api(actor.page, path, { ...options, sessionID })).status, 403);
    assert.equal((await api(actor.page, '/api/v1/users/me')).status, 200, 'Legal denial signed out an ordinary valid session');
  }
  await open(dpo.page, harness, '/admin/legal');
  const before = harness.originEvidence.legal;
  const holdForm = dpo.page.getByRole('form', { name: localizedText('Read Legal Holds'), exact: true });
  await holdForm.getByLabel(localizedText('Original account reference'), { exact: true }).fill('invalid');
  await holdForm.getByRole('button', { name: localizedText('Read Legal Holds'), exact: true }).click();
  await holdForm.getByRole('alert').waitFor();
  assert.equal(harness.originEvidence.legal, before, 'Invalid legal reference became an unfiltered request');
  for (const query of ['account_ref=', 'account_ref=%zz', 'limit=1&limit=2', 'email=not-an-identity'])
    assert.equal((await api(dpo.page, `${holdsPath}?${query}`)).status, 400);
  const sessionID = (await api(dpo.page, '/api/v1/users/me')).body.session.id;
  assert.equal((await api(dpo.page, holdsPath, { method: 'POST', body: hold, sessionID, idempotencyKey: recordedOperation })).status, 403);
  assert.equal((await api(dpo.page, holdsPath)).status, 200, 'Eligible legal read incorrectly required step-up');
  assert.equal(state(deleted).eligible_records, 0);
  evidence.checks.push('DPO legal admission; direct-route and all legal operation denials for Support/Moderator/Super-Admin without ordinary-session logout; strict empty/malformed filters and fresh-step-up boundary');

  checkpoint = 'legal-independent-requests';
  const created = await create(dpo, hold, recordedOperation, { double: true });
  assert.equal(state(deleted).total, 1);
  const replayed = await create(dpo, hold, recordedOperation, { replay: true });
  assert.equal(replayed.id, created.id);
  await create(dpo, { ...hold, reason: `${markers.reason} changed input` }, recordedOperation, { status: 409 });
  await dpo.page.getByRole('main').getByRole('alert').filter({ hasText: localizedText(/original operation conflicts/) }).waitFor();
  assert.equal(state(deleted).total, 1, 'Changed-input conflict silently replaced the original request');
  const preservation = await create(dpo, preserve(deleted), recordedOperation, { method: 'totp' });
  assert.notEqual(preservation.hold.id, created.id);
  assert(!preservation.account_present && preservation.ledger_evidence_present);
  assert((await dpo.page.getByTestId('legal-outcome').textContent()).includes(preservation.note));
  const preservedReplay = await create(dpo, preserve(deleted), recordedOperation, { replay: true });
  assert(preservedReplay.replayed && !preservedReplay.hold.replayed, 'Top-level preservation replay must be authoritative');
  await exercisePreferenceSwitch(dpo.page, { privateSelector: '[data-legal-private] input, [data-legal-private] textarea' });
  const currentPreservation = await create(dpo, preserve(current), recordedOperation);
  assert(currentPreservation.account_present && currentPreservation.ledger_evidence_present);
  assert.notEqual(currentPreservation.hold.id, preservation.hold.id, 'A reused UUID incorrectly merged distinct account references');
  const absentPreservation = await create(dpo, preserve(absent), randomUUID());
  assert(!absentPreservation.account_present && !absentPreservation.ledger_evidence_present && absentPreservation.hold.is_active);
  const all = await readHolds(dpo, undefined, 2);
  assert.equal(all.limit, 2);
  assert.equal(all.items.length, 2);
  assert(all.total >= 4);
  assert(!(await dpo.page.getByRole('main').textContent()).includes(markers.reason), 'Restricted narrative opened without an explicit detail action');
  const page = await readHolds(dpo, deleted, 1);
  assert.equal(page.total, 2);
  assert.equal(page.items.length, 1);
  const nextRead = response(dpo.page, holdsPath, 'GET', 200);
  await dpo.page.getByRole('button', { name: localizedText('Next hold page'), exact: true }).click();
  assert.equal((await nextRead).body.offset, 1);
  await layout(dpo.page, 'legal-holds', evidence, artifactDirectory);
  await dpo.page.getByTestId('legal-hold-row').first().getByRole('button', { name: localizedText('View restricted details'), exact: true }).click();
  const details = dpo.page.getByTestId('legal-hold-details');
  await details.waitFor();
  assert((await details.textContent()).includes(markers.reason));
  assert.equal(await details.locator('img, script, iframe, a[href]').count(), 0);
  await layout(dpo.page, 'legal-narrative', evidence, artifactDirectory);
  await dpo.page.keyboard.press('Escape');
  await release(dpo, deleted, created.id);
  assert.equal(state(deleted).active, 1, 'Release removed another independent preservation request');
  const releasedReplay = await create(dpo, hold, recordedOperation, { replay: true });
  assert(!releasedReplay.is_active && releasedReplay.id === created.id && state(deleted).active === 1);
  for (const role of ['support', 'moderator', 'super_admin']) assert.equal((await api(actors[role].page, `${holdsPath}/${created.id}`, { method: 'DELETE',
    sessionID: (await api(actors[role].page, '/api/v1/users/me')).body.session.id })).status, 403);
  evidence.checks.push('both legal create forms with externally recorded UUIDs, native UV/TOTP, synchronous double-submit protection, independent target/kind scopes, authoritative replay including released state, advisory past dates and preservation presence observations');

  checkpoint = 'legal-attribution';
  const core = await lookup(dpo);
  assert.equal(core.body.items.length, 4);
  assert.deepEqual([...new Set(core.body.items.map((row) => row.account_ref))].sort(), [deleted, current].sort());
  const coreFields = ['id', 'account_ref', 'event_type', 'timestamp', 'retain_until', 'seq'].sort();
  assert(core.body.items.every((row) => JSON.stringify(Object.keys(row).sort()) === JSON.stringify(coreFields) &&
    typeof row.seq === 'string' && BigInt(row.seq) > BigInt(Number.MAX_SAFE_INTEGER)));
  assert(typeof core.body.coverage.through_seq === 'string' && BigInt(core.body.coverage.through_seq) > BigInt(Number.MAX_SAFE_INTEGER));
  assert(!JSON.stringify(core.body).includes(fixture.email));
  for (const key of ['identity_blind_index', 'blind_index_version', 'payload', 'chain_hash', 'email', 'phone'])
    assert(!JSON.stringify(core.body).includes(`"${key}"`), 'Forbidden attribution projection escaped the real API');
  assert.equal((await api(dpo.page, legalLookup, { method: 'POST', sessionID,
    stepUpToken: core.response.request().headers()['x-step-up-auth'], body: inquiry })).status, 403, 'A consumed lookup grant was reusable');
  await dpo.page.getByTestId('legal-result-row').filter({ hasText: localizedText(deleted) }).first()
    .getByRole('button', { name: localizedText('Select reference'), exact: true }).click();
  assert.equal(await dpo.page.getByTestId('legal-selected-reference').count(), 1);
  const inline = await create(dpo, hold, randomUUID(), { pinned: true });
  assert.equal(inline.account_ref, deleted);
  assert(!state(deleted).account_present);
  const scopedQuery = { ...inquiry, limit: 1, fields: Object.keys(fields) };
  const first = await lookup(dpo, scopedQuery);
  assert.equal(first.body.items.length, 1);
  assert(first.body.next_cursor && first.body.items[0].account_ref === deleted);
  for (const key of Object.keys(fields)) assert.equal(first.body.items[0][key], fixture.metadata[key]);
  assert.equal(await dpo.page.evaluate(() => Boolean(globalThis.__legalPayloadExecuted)), false);
  await layout(dpo.page, 'legal-attribution', evidence, artifactDirectory);
  // A different operator acts through the existing independent signed probe,
  // without activating another tab and correctly clearing this inquiry page.
  const remoteSession = (await api(combined.page, '/api/v1/users/me')).body.session.id;
  const challenge = await api(combined.page, '/api/v1/auth/stepup/challenge', { method: 'POST', sessionID: remoteSession, body: {} });
  assert.equal(challenge.status, 200);
  assert(challenge.body.methods.includes('totp'));
  const remoteGrant = await api(combined.page, '/api/v1/auth/stepup/verify', {
    method: 'POST', sessionID: remoteSession, body: { method: 'totp', code: harness.fixture('totp-code', { user_id: combined.fixture.user_id }).code },
  });
  assert.equal(remoteGrant.status, 200);
  verificationCount++;
  verificationTimes.set(combined, [Date.now()]);
  harness.secrets.push(remoteGrant.body.token);
  harness.legalSecrets.add(remoteGrant.body.token);
  const released = await api(combined.page, `${holdsPath}/${currentPreservation.hold.id}`, {
    method: 'DELETE', sessionID: remoteSession, stepUpToken: remoteGrant.body.token,
  });
  assert.equal(released.status, 204);
  remoteGrant.body.token = '';
  assert.equal(state(current).eligible_records, 0, 'Released expired evidence stayed eligible');
  const appended = harness.fixture('admin-legal-append', { account_ref: deleted });
  assert(BigInt(appended.through_seq) > BigInt(first.body.coverage.through_seq));
  const nextButton = dpo.page.getByRole('button', { name: localizedText('Next attribution page'), exact: true });
  await nextButton.waitFor();
  const { dialog: nextDialog } = await verify(dpo, nextButton);
  const continued = response(dpo.page, legalLookup, 'POST', 200);
  await confirm(nextDialog, 'Confirm lookup');
  const continuation = await continued;
  assert.deepEqual(continuation.response.request().postDataJSON(), { ...first.response.request().postDataJSON(), cursor: first.body.next_cursor });
  assert.equal(continuation.body.coverage.through_seq, first.body.coverage.through_seq);
  assert.equal(continuation.body.coverage.observed_at, first.body.coverage.observed_at);
  assert(Date.parse(continuation.body.coverage.eligibility_checked_at) >= Date.parse(first.body.coverage.eligibility_checked_at));
  assert.equal(continuation.body.items.length, 1);
  assert.equal(continuation.body.items[0].account_ref, deleted);
  assert(BigInt(continuation.body.items[0].seq) > BigInt(first.body.items[0].seq));
  assert(!continuation.body.next_cursor, 'Release or the captured high-water was ignored on the next page');
  assert((await dpo.page.getByTestId('legal-coverage').textContent()).includes(continuation.body.coverage.note));
  evidence.checks.push('post-deletion inline reference selection without profile lookup, separate historical references, opt-in-only inert metadata, exact decimal sequences above JS safe max, one-use fresh verification per page, frozen scope/high-water and current hold eligibility after real release and later signer ingestion');

  checkpoint = 'legal-audit-rollback';
  await section(second, 'Legal Holds');
  let verified = await verify(second, second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
  const failedKey = randomUUID();
  await fillCreate(verified.dialog, { ...hold, account_ref: current }, failedKey);
  const beforeFailure = state(current);
  harness.fixture('admin-audit-failure', { scenario: 'on' });
  try {
    const failed = response(second.page, holdsPath, 'POST', 503);
    await confirm(verified.dialog, 'Confirm Legal Hold');
    assert.equal((await failed).body.error, 'audit_unavailable');
    await second.page.getByTestId('legal-outcome').waitFor();
    assert.equal(await second.page.getByTestId('legal-outcome').getAttribute('data-outcome'), 'unconfirmed');
    assert.deepEqual(state(current), beforeFailure, 'Failed durable audit committed a legal create');
  } finally { harness.fixture('admin-audit-failure', { scenario: 'off' }); }
  verified = { dialog: await prepareRelease(second, deleted, preservation.hold.id) };
  harness.fixture('admin-audit-failure', { scenario: 'on' });
  try {
    const failed = response(second.page, `${holdsPath}/${preservation.hold.id}`, 'DELETE', 503);
    await confirm(verified.dialog, 'Confirm release');
    assert.equal((await failed).body.error, 'audit_unavailable');
    assert(state(deleted, recordedOperation, 'preservation').is_active, 'Failed durable audit committed a release');
  } finally { harness.fixture('admin-audit-failure', { scenario: 'off' }); }
  verified = await prepareLookup(second);
  harness.fixture('admin-audit-failure', { scenario: 'on' });
  try {
    const failed = response(second.page, legalLookup, 'POST', 503);
    await confirm(verified.dialog, 'Confirm lookup');
    const body = (await failed).body;
    assert.deepEqual(body, { error: 'audit_unavailable' }, 'Failed durable audit disclosed legal records');
    assert.equal(await second.page.getByTestId('legal-result-row').count(), 0);
  } finally { harness.fixture('admin-audit-failure', { scenario: 'off' }); }
  evidence.checks.push('real PostgreSQL admin-outbox rejection rolls back legal create/release and withholds attribution bytes; UI keeps transmitted write outcome unconfirmed rather than claiming rollback');

  checkpoint = 'legal-lost-writes';
  const lostKey = randomUUID();
  const lostPayload = { ...hold, account_ref: current };
  await section(dpo, 'Legal Holds');
  verified = await verify(dpo, dpo.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
  await fillCreate(verified.dialog, lostPayload, lostKey);
  let lostID;
  evidence.legalLostCreate = await lostWrite(dpo, holdsPath, 201,
    () => confirm(verified.dialog, 'Confirm Legal Hold'), async () => {
      const committed = state(current, lostKey);
      assert(committed.is_active && committed.active === 1);
      lostID = committed.hold_id;
      await readHolds(dpo, current);
      assert.equal(await dpo.page.getByTestId('legal-outcome').getAttribute('data-outcome'), 'unconfirmed', 'A list inferred which uncertain operation committed');
    });
  const recovered = await create(dpo, lostPayload, lostKey, { replay: true });
  assert.equal(recovered.id, lostID);
  verified = { dialog: await prepareRelease(dpo, current, lostID) };
  evidence.legalLostRelease = await lostWrite(dpo, `${holdsPath}/${lostID}`, 204,
    () => confirm(verified.dialog, 'Confirm release'), async () => {
      assert(!state(current, lostKey).is_active);
      await readHolds(dpo, current);
      assert.equal(await dpo.page.getByTestId('legal-outcome').getAttribute('data-outcome'), 'unconfirmed');
    });
  harness.fixture('admin-legal-cleanup', { account_ref: current });
  await create(dpo, lostPayload, lostKey, { status: 409 });
  await dpo.page.getByRole('main').getByRole('alert').filter({ hasText: localizedText(/original operation conflicts/) }).waitFor();
  assert(state(current).purged > 0 && state(current).active === 0);
  await readHolds(dpo, current);
  for (const failure of [
    { status: 200, body: '{"items":' },
    { status: 200, body: JSON.stringify({ padding: 'x'.repeat(4 * 1024 * 1024) }) },
    { status: 429, headers: { 'Retry-After': '2' }, body: '{"error":"rate_limit_exceeded"}' },
    { status: 503, body: '{"error":"audit_unavailable"}' },
  ]) {
    await queryFault(dpo.page, holdsPath, () => dpo.page.getByRole('button', { name: localizedText('Read Legal Holds'), exact: true }).click(), failure);
    assert.equal(await dpo.page.getByTestId('legal-hold-row').count(), 0);
  }
  evidence.checks.push('real committed-but-lost create and release responses with every outgoing attempt observed through read-only reconciliation; explicit same-tuple fresh-grant recovery, no automatic/fresh-key replay, cleaned narrative tombstone conflict without recreation');

  checkpoint = 'legal-privacy';
  await section(second, 'Legal Holds');
  const unsent = observeLegalWrites(second.authenticator.cdp, harness.origin);
  try {
    verified = await verify(second, second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
    const input = await verified.dialog.getByLabel(localizedText('Reason'), { exact: true }).elementHandle();
    const draftKey = randomUUID();
    harness.secrets.push(draftKey);
    harness.legalSecrets.add(draftKey);
    await verified.dialog.getByLabel(localizedText('Original account reference'), { exact: true }).fill(deleted);
    await verified.dialog.getByLabel(localizedText('Operation UUID'), { exact: true }).fill(draftKey);
    await verified.dialog.getByLabel(localizedText('Requesting authority'), { exact: true }).fill(markers.requesting_authority);
    await verified.dialog.getByLabel(localizedText('Legal basis'), { exact: true }).fill(markers.legal_basis);
    await input.fill('\u00e9'.repeat(2049));
    await verified.dialog.getByRole('button', { name: localizedText('Review request'), exact: true }).click();
    await verified.dialog.getByRole('alert').waitFor();
    assert.equal(unsent.count, 0, 'Oversized UTF-8 legal narrative reached a write');
    await input.fill(markers.cancelledDraft);
    await second.page.keyboard.press('Escape');
    await verified.dialog.waitFor({ state: 'hidden' });
    assert(await input.evaluate((element) => element.value === '' && element.defaultValue === '' && element.textContent === ''),
      'Legal cancellation left detached narrative input');
    await input.dispose();
    verified = await verify(second, second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
    const expired = await verified.dialog.getByLabel(localizedText('Reason'), { exact: true }).elementHandle();
    await expired.fill(markers.expiredDraft);
    await second.page.getByRole('main').getByRole('alert').filter({ hasText: localizedText(/Verification expired/) }).waitFor({ timeout: 30_000 });
    assert(await expired.evaluate((element) => element.value === '' && element.defaultValue === '' && element.textContent === ''),
      'Grant expiry left a detached legal narrative');
    await expired.dispose();
    await second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }).click();
    let dialog = second.page.getByTestId('stepup-dialog');
    await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
    await dialog.getByRole('button', { name: localizedText('Use authenticator code'), exact: true }).click();
    await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).fill('123');
    const resume = await hidePortal(second.page, second.context, evidence, 'admin-ready');
    await resume();
    await second.page.getByTestId('admin-ready').waitFor();
    dialog = second.page.getByTestId('stepup-dialog');
    await dialog.waitFor();
    await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
    assert.equal(await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).inputValue(), '');
    await second.page.keyboard.press('Escape');
    verified = await verify(second, second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
    const hidden = await verified.dialog.getByLabel(localizedText('Reason'), { exact: true }).elementHandle();
    await hidden.fill(markers.backgroundDraft);
    const returnToPage = await hidePortal(second.page, second.context, evidence, 'admin-ready');
    await returnToPage();
    await second.page.getByTestId('admin-ready').waitFor();
    assert(await hidden.evaluate((element) => element.value === '' && element.defaultValue === '' && element.textContent === ''),
      'Hiding legal workflow left detached sensitive input');
    await hidden.dispose();
    assert.equal(await second.page.getByTestId('stepup-dialog').count(), 0);
    assert.equal(unsent.count, 0);
  } finally { unsent.close(); }

  // Delay a real successful disclosure at Chromium's response boundary; never
  // fetch/replay it through a second HTTP stack or save its body in an artifact.
  const cdp = second.authenticator.cdp;
  verified = await prepareLookup(second);
  const arrived = deferred();
  let pausedID;
  const pause = (event) => {
    if (event.request.method === 'POST' && event.responseStatusCode === 200) {
      pausedID = event.requestId;
      arrived.resolve(true);
    } else void cdp.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => arrived.resolve(false));
  };
  cdp.on('Fetch.requestPaused', pause);
  const lateTimer = setTimeout(() => arrived.resolve(false), 15_000);
  try {
    await cdp.send('Fetch.enable', { patterns: [{ urlPattern: harness.origin + legalLookup, requestStage: 'Response' }] });
    await confirm(verified.dialog, 'Confirm lookup');
    assert(await arrived.promise, 'Expected a real paused legal disclosure');
    const resume = await hidePortal(second.page, second.context, evidence, 'admin-ready');
    assert.equal(await second.page.getByTestId('legal-result-row').count(), 0);
    await cdp.send('Fetch.continueRequest', { requestId: pausedID }).catch(() => {});
    await resume();
    await second.page.getByTestId('admin-ready').waitFor();
    assert.equal(await second.page.getByTestId('legal-result-row').count(), 0);
    assert.equal(await second.page.getByTestId('legal-coverage').count(), 0);
  } finally { clearTimeout(lateTimer); cdp.off('Fetch.requestPaused', pause); await cdp.send('Fetch.disable'); }
  await section(dpo, 'Preservation');
  assert.equal(await dpo.page.getByTestId('legal-result-row').count(), 0);
  await section(dpo, 'Attribution');
  assert.equal(await dpo.page.getByTestId('legal-selected-reference').count(), 0);
  assert.equal(await dpo.page.getByTestId('legal-coverage').count(), 0);
  const noScript = await dpo.context.browser().newContext({ javaScriptEnabled: false, serviceWorkers: 'block' });
  try {
    await noScript.addCookies(await dpo.context.cookies(harness.origin));
    const document = await noScript.newPage();
    const shell = await visit(document, harness.origin, '/admin/legal');
    const html = await shell.text();
    assert(![...harness.legalSecrets].some((value) => html.includes(value)), 'Legal private material was server-rendered');
    assert.equal(await document.locator('form, input, textarea, table, [data-legal-private]').count(), 0);
  } finally { await noScript.close(); }
  for (const actor of [dpo, second, combined])
    await assertAdminPrivacy(actor.page, actor.observed, { ...markers, ...Object.fromEntries([...harness.legalSecrets].map((value, index) => [index, value])) });
  evidence.checks.push('legal narrative/row/coverage screenshot masks, inert text, desktop/320px light/dark keyboard dialog checks, empty SSR/no-JavaScript shell, no legal URL/history/storage/console/telemetry copies, cancellation/grant-expiry/hide detached-input clearing, TOTP intent-only resume, section clearing and ignored late real disclosure');

  checkpoint = 'legal-revocation';
  await section(combined, 'Legal Holds');
  verified = await verify(combined, combined.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
  await fillCreate(verified.dialog, hold, randomUUID());
  harness.fixture('admin-revoke', { user_id: combined.fixture.user_id, role: 'dpo' });
  const denied = response(combined.page, holdsPath, 'POST', 403);
  await confirm(verified.dialog, 'Confirm Legal Hold');
  assert.equal((await denied).body.error, 'forbidden');
  await combined.page.getByTestId('stepup-dialog').waitFor({ state: 'hidden' });
  assert.equal((await api(combined.page, '/api/v1/users/me')).status, 200);
  await open(combined.page, harness, '/admin/legal');
  assert.equal(await combined.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }).count(), 0);

  await section(second, 'Legal Holds');
  verified = await verify(second, second.page.getByRole('button', { name: localizedText('Apply Legal Hold'), exact: true }));
  const expiring = await verified.dialog.getByLabel(localizedText('Reason'), { exact: true }).elementHandle();
  await expiring.fill(markers.sessionDraft);
  const active = (await api(second.page, '/api/v1/users/me')).body.session.id;
  harness.fixture('expire-session', { user_id: second.fixture.user_id, session_id: active });
  await visit(second.page, harness.origin, '/admin/legal');
  await second.page.getByTestId('admin-ready').waitFor({ state: 'hidden' });
  // Navigation destroys the old execution context; privacy of detached controls
  // within one context is checked above, and the replacement shell is inspected.
  await expiring.dispose();
  assert.equal(await second.page.getByLabel(localizedText('Reason'), { exact: true }).count(), 0);
  assert.equal(await second.page.getByTestId('legal-outcome').count(), 0);
  assert.equal(await second.page.getByRole('link', { name: localizedText('Sign in with a passkey'), exact: true }).getAttribute('href'), '/login?returnTo=%2Fadmin%2Flegal');
  evidence.legalVerifications = verificationCount;
  evidence.checks.push('live legal capability revocation after fresh verification clears privileged controls without normal logout; real legal-session expiry drops pending input and returns only the fixed legal path');
}

export async function validateAdmin(harness, { artifactDirectory } = {}) {
  const evidence = { locale: browserLocale(), checks: [], layouts: 0, nativeHiddenTabObserved: false, nativeBfcacheRestoreObserved: false };
  const markerID = randomBytes(16).toString('hex');
  const markers = Object.fromEntries(['reason', 'cancelledDraft', 'backgroundDraft', 'expiredDraft']
    .map((kind) => [kind, `admin-private-${kind}-${markerID}`]));
  const legalMarkers = Object.fromEntries(['reason', 'requesting_authority', 'legal_basis', 'case_reference', 'purpose',
    'cancelledDraft', 'backgroundDraft', 'expiredDraft', 'sessionDraft']
    .map((kind) => [kind, `legal-private-${kind}-${markerID}`]));
  legalMarkers.reason = `<img src=x onerror=globalThis.__legalPayloadExecuted=true> ${legalMarkers.reason}`;
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
    for (const role of ['ordinary', 'support', 'moderator', 'dpo', 'super_admin', 'combined', 'legal_operator']) {
      const fixture = harness.fixture('admin-seed', { role: role === 'legal_operator' ? 'dpo' : role });
      const { context, observed } = await newContext(browser, harness);
      contexts.push(context);
      observeAdminMarkers(context, harness, markers, observed.failures);
      observeLegalPrivacy(context, harness, legalMarkers, observed.failures);
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
      for (const flag of ['legal_holds_read', 'legal_holds_apply', 'legal_holds_release', 'preservation_requests_create', 'legal_inquiry_lookup'])
        assert.equal(access[flag], ['dpo', 'combined'].includes(role));
      assert.equal(caps.body.limits.chain_verify_max_limit, 5);
      if (!access.users_read) assert.equal(await page.getByRole('link', { name: localizedText('Accounts'), exact: true }).count(), 0);
      if (!access.audit_logs_read) assert.equal(await page.getByRole('link', { name: localizedText('Audit logs'), exact: true }).count(), 0);
      if (!access.legal_holds_read) assert.equal(await page.locator('a[href="/admin/legal"]').count(), 0);
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

    await validateLegal(harness, actors, evidence, artifactDirectory, legalMarkers);
    harness.assertPrivateLogs();

    checkpoint = 'admin-directory';
    await open(support, harness, '/admin/users');
    assert.equal(await support.getByLabel(localizedText('Exact email'), { exact: true }).count(), 0);
    const list = operationResponse(support, '/api/v1/admin/users', 'GET');
    await support.getByRole('button', { name: localizedText('Apply filters'), exact: true }).click();
    const supportBody = await (await list).json();
    assert(supportBody.items.length > 0 && supportBody.items.length <= 5);
    assert(supportBody.items.every((item) => !('email' in item) && typeof item.lifecycle_revision === 'string'));
    await support.getByTestId('admin-account-row').first().waitFor();
    assert.equal(await support.getByRole('columnheader', { name: localizedText('Email'), exact: true }).count(), 0);
    const next = operationResponse(support, '/api/v1/admin/users', 'GET');
    await support.getByRole('button', { name: localizedText('Next page'), exact: true }).click();
    const nextAccounts = await (await next).json();
    assert.equal(nextAccounts.offset, 5);
    for (const account of nextAccounts.items)
      await support.getByRole('link', { name: localizedText(`View account ${account.id}`), exact: true }).waitFor();
    await layout(support, 'accounts', evidence, artifactDirectory);
    const skip = support.getByRole('link', { name: localizedText('Skip to admin content'), exact: true });
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
    await moderator.getByLabel(localizedText('Exact email'), { exact: true }).fill(target.email);
    await moderator.getByRole('button', { name: localizedText('Find account'), exact: true }).click();
    const found = await lookup;
    assert.equal(new URL(found.url()).search, '');
    assert.deepEqual(found.request().postDataJSON(), { email: target.email });
    assert.equal((await found.json()).items[0].id, target.user_id);
    await moderator.getByRole('link', { name: localizedText(`View account ${target.user_id}`), exact: true }).click();
    await moderator.getByTestId('admin-ready').waitFor();
    await moderator.getByRole('heading', { name: localizedText(target.user_id), exact: true }).waitFor();
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
      const reason = await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).elementHandle();
      await reason.fill(markers.cancelledDraft);
      await assertAdminPrivacy(moderator, actors.moderator.observed, markers);
      await layout(moderator, 'confirmation', evidence, artifactDirectory);
      await moderator.keyboard.press('Escape');
      await dialog.waitFor({ state: 'hidden' });
      assert(await reason.evaluate((element) => element.value === ''), 'Cancelled reason remained on the detached input');
      await reason.dispose();
      assert(await moderator.getByRole('button', { name: localizedText('Suspend'), exact: true }).evaluate((element) => element === document.activeElement));
      assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'active');
      assert.equal(cancelledPatches.count, 0, 'Pre-send cancellation transmitted a status PATCH');
    } finally { cancelledPatches.close(); }

    // The server, not visible status text, protects a pin from a profile/ABA edit.
    dialog = await confirmForm(moderator);
    harness.fixture('admin-revision', { user_id: target.user_id });
    const conflict = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    assert.equal((await conflict).status(), 409);
    await moderator.getByRole('alert').filter({ hasText: localizedText(/account changed/i) }).waitFor();
    assert.equal(await moderator.getByLabel(localizedText('Moderation reason'), { exact: true }).count(), 0);
    await moderator.getByRole('button', { name: localizedText('Read current state'), exact: true }).click();
    await moderator.getByRole('button', { name: localizedText('Suspend'), exact: true }).waitFor();

    dialog = await confirmForm(moderator);
    const changed = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    const changedResponse = await changed;
    assert.equal(changedResponse.status(), 204);
    assert.deepEqual(Object.keys(changedResponse.request().postDataJSON()).sort(), ['expected_revision', 'reason', 'status']);
    assert.equal(typeof changedResponse.request().postDataJSON().expected_revision, 'string');
    await moderator.getByText(localizedText('Status change confirmed. Current account state loaded.'), { exact: true }).waitFor();
    assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'suspended');
    assert.equal((await api(ordinary, '/api/v1/users/me')).status, 401, 'Suspension left an old normal session usable');
    dialog = await confirmForm(moderator, 'Reactivate', 'totp', harness, actors.moderator.fixture);
    const restored = operationResponse(moderator, statusPath, 'PATCH');
    await finalSubmit(dialog, markers.reason, 'reactivate');
    assert.equal((await restored).status(), 204);
    await moderator.getByText(localizedText('Status change confirmed. Current account state loaded.'), { exact: true }).waitFor();
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
      await moderator.getByText(localizedText(/Outcome unconfirmed; the action was not retried/)).waitFor();
      await Promise.all(interceptions);
      assert.equal(interceptionFailed, false, 'Native response interception failed');
      assert.equal(committed, 1);
      lostPatches.assertLostResponse();
      assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'banned');
      assert.equal(await moderator.getByRole('heading', { name: localizedText(target.user_id), exact: true }).count(), 0);
      lostPatches.reconcile();
      const reread = operationResponse(moderator, `/api/v1/admin/users/${target.user_id}`, 'GET');
      await moderator.getByRole('button', { name: localizedText('Read current state'), exact: true }).click();
      assert.equal((await reread).status(), 200);
      await moderator.getByRole('heading', { name: localizedText(target.user_id), exact: true }).waitFor();
      assert(await moderator.getByText(localizedText(/matching status proves only current state/)).isVisible());
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
      const button = combined.getByRole('button', { name: localizedText('Suspend'), exact: true });
      await button.waitFor();
      assert(await button.isDisabled());
    }
    await open(combined, harness, `/admin/users/${actors.dpo.fixture.user_id}`);
    dialog = await confirmForm(combined);
    const protectedResponse = operationResponse(combined, `/api/v1/admin/users/${actors.dpo.fixture.user_id}/status`, 'PATCH');
    await finalSubmit(dialog, markers.reason);
    assert.equal((await protectedResponse).status(), 403);
    await combined.getByText(localizedText('The status change was not permitted. No change was confirmed.'), { exact: true }).waitFor();
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
      await combined.getByRole('button', { name: localizedText('Suspend'), exact: true }).click();
      dialog = combined.getByTestId('stepup-dialog');
      await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
      await dialog.getByRole('button', { name: localizedText('Use authenticator code'), exact: true }).click();
      await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).fill('123');
      const resume = await hidePortal(combined, actors.combined.context, evidence, 'admin-ready');
      await resume();
      await combined.getByTestId('admin-ready').waitFor();
      await dialog.getByText(localizedText(/Your pending action was restored/)).waitFor();
      await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
      assert.equal(await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).inputValue(), '');
      await dialog.getByRole('button', { name: localizedText('Cancel'), exact: true }).click();
      dialog = await confirmForm(combined);
      const backgroundReason = await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).elementHandle();
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
      const expiredReason = await dialog.getByLabel(localizedText('Moderation reason'), { exact: true }).elementHandle();
      await expiredReason.fill(markers.expiredDraft);
      await combined.getByRole('alert').filter({ hasText: localizedText(/Verification expired/) }).waitFor({ timeout: 30_000 });
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
    assert.equal(await combined.getByLabel(localizedText('Moderation reason'), { exact: true }).count(), 0);
    assert.equal((await api(combined, '/api/v1/users/me')).status, 200);
    evidence.checks.push('permission revocation after grant clears private state without logging out the normal session');

    checkpoint = 'admin-audit';
    await open(dpo, harness, '/admin/audit-logs');
    await dpo.getByLabel(localizedText('Event type (exact)'), { exact: true }).fill(audit.event_type);
    await dpo.getByLabel(localizedText('Page size'), { exact: true }).fill('20');
    const logs = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: localizedText('Search audit logs'), exact: true }).click();
    const logsResponse = await logs;
    const logBody = await logsResponse.json();
    const logText = JSON.stringify(logBody);
    assert(Buffer.byteLength(logText) > 256 * 1024 && Buffer.byteLength(logText) < 4 * 1024 * 1024);
    assert(logText.includes(markers.auditPayload), 'Signed audit response did not carry the controlled payload marker');
    assert(logBody.items.every((row) => typeof row.seq === 'string'));
    assert(logBody.items.some((row) => BigInt(row.seq) > BigInt(Number.MAX_SAFE_INTEGER)));
    const initialQuery = new URL(logsResponse.url()).searchParams;
    assert(initialQuery.get('start_time').endsWith('Z') && initialQuery.get('end_time').endsWith('Z'));
    await dpo.getByRole('button', { name: localizedText(/^View details for sequence /) }).first().click();
    const details = dpo.getByRole('dialog', { name: localizedText('Audit record details'), exact: true });
    await details.waitFor();
    assert((await details.textContent()).includes(markers.auditPayload), 'Audit details did not render the controlled payload as text');
    assert.equal(await details.locator('img, script, iframe, a[href]').count(), 0);
    assert.equal(await dpo.evaluate(() => Boolean(globalThis.__adminPayloadExecuted)), false);
    await assertAdminPrivacy(dpo, actors.dpo.observed, markers);
    await dpo.keyboard.press('Escape');
    await dpo.getByLabel(localizedText('Page size'), { exact: true }).fill('2');
    const firstPage = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: localizedText('Search audit logs'), exact: true }).click();
    const firstResponse = await firstPage;
    const first = await firstResponse.json();
    assert(first.has_more && typeof first.next_before_seq === 'string');
    const older = operationResponse(dpo, '/api/v1/admin/audit-logs', 'GET');
    await dpo.getByRole('button', { name: localizedText('Older records'), exact: true }).click();
    const olderResponse = await older;
    const olderQuery = new URL(olderResponse.url()).searchParams;
    assert.equal(olderQuery.get('before_seq'), first.next_before_seq);
    for (const key of ['start_time', 'end_time', 'event_type', 'limit'])
      assert.equal(olderQuery.get(key), new URL(firstResponse.url()).searchParams.get(key));
    const olderBody = await olderResponse.json();
    assert(olderBody.items.every((row) => BigInt(row.seq) < BigInt(first.next_before_seq)));
    // An upstream capture finishes before React accepts and renders that page.
    for (const row of olderBody.items)
      await dpo.getByRole('button', { name: localizedText(`View details for sequence ${row.seq}`), exact: true }).waitFor();
    await layout(dpo, 'audit', evidence, artifactDirectory);
    evidence.checks.push('real signed audit list exceeds 256KiB within its 4MiB budget, exact high-int64 keyset pages, UTC frozen filters, inert payload dialog');

    checkpoint = 'admin-read-failures';
    for (const failure of [
      { status: 429, headers: { 'Retry-After': '2' }, body: '{"error":"rate_limit_exceeded"}' },
      { status: 503, body: '{"error":"audit_unavailable"}' },
      { status: 200, body: '{"items":' },
      { status: 200, body: JSON.stringify({ padding: 'x'.repeat(4 * 1024 * 1024) }) },
    ]) {
      await queryFault(dpo, '/api/v1/admin/audit-logs', () => dpo.getByRole('button', { name: localizedText('Search audit logs'), exact: true }).click(), failure);
      assert.equal(await dpo.getByRole('button', { name: localizedText(/^View details for sequence /) }).count(), 0);
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
    await dpo.getByRole('button', { name: localizedText('Start new run'), exact: true }).click();
    const initial = await (await firstProof).json();
    assert.equal(initial.canonical_version, 2, 'Verifier must declare its canonical format');
    assert.equal(initial.verified, true, 'Untampered fixture chain must verify');
    assert.equal(initial.complete, false, 'The bounded first page must remain partial');
    assert.equal(initial.after_seq, '0');
    assert.equal(typeof initial.through_seq, 'string');
    assert.equal(initial.scope, 'database_relative_chain_and_retained_leaves; not complete ingestion, independent historical authenticity, or legal authorization');
    harness.fixture('admin-audit', { user_id: target.user_id });
    const continuation = operationResponse(dpo, '/api/v1/admin/audit-logs/verify', 'GET');
    await dpo.getByRole('button', { name: localizedText('Continue verification'), exact: true }).click();
    const continuedResponse = await continuation;
    const continuedQuery = new URL(continuedResponse.url()).searchParams;
    assert.equal(continuedQuery.get('through_seq'), initial.through_seq);
    assert.equal(continuedQuery.get('after_seq'), initial.next_after_seq);
    assert.equal(continuedQuery.get('predecessor_hash'), initial.last_hash);
    await dpo.getByRole('button', { name: localizedText('Stop verification'), exact: true }).click();
    await dpo.getByText(localizedText(/No complete-run conclusion was reached/)).waitFor();
    await layout(dpo, 'integrity', evidence, artifactDirectory);
    const verifier = actors.super_admin.page;
    await open(verifier, harness, '/admin/integrity');
    assert.equal((await api(verifier, '/api/v1/admin/users')).status, 403);
    assert.equal((await api(verifier, '/api/v1/admin/audit-logs')).status, 403);
    await verifier.getByLabel(localizedText('Chain'), { exact: true }).selectOption('ledger');
    const ledgerProof = operationResponse(verifier, '/api/v1/admin/ledger/verify', 'GET');
    await verifier.getByRole('button', { name: localizedText('Start new run'), exact: true }).click();
    const ledgerResult = await (await ledgerProof).json();
    assert.equal(ledgerResult.chain, 'ledger');
    assert.equal(ledgerResult.scope, 'database_relative_chain_retained_leaves_and_erasure_annotations; annotations do not prove receipt chaining or legal authorization; not complete ingestion or independent historical authenticity');
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
      hasText: localizedText('Your session is no longer available. Sign in again to continue.'),
    }).waitFor();
    assert.equal(await support.getByTestId('admin-ready').count(), 0);
    assert.equal(await support.getByRole('link', { name: localizedText('Sign in with a passkey'), exact: true }).getAttribute('href'), '/login?returnTo=%2Fadmin%2Fusers');
    evidence.checks.push('background/history discard proof progress; real session expiry clears private data and strips detail identifiers from login returnTo');

    await open(moderator, harness, detailPath);
    const sibling = await actors.moderator.context.newPage();
    await visit(sibling, harness.origin, '/dashboard');
    await sibling.getByTestId('portal-ready').waitFor();
    await sibling.getByRole('button', { name: localizedText('Sign out'), exact: true }).click();
    await sibling.waitForURL(harness.origin + '/login');
    await moderator.bringToFront();
    await moderator.getByTestId('admin-ready').waitFor({ state: 'hidden' });
    assert.equal(await moderator.getByRole('heading', { name: localizedText(target.user_id), exact: true }).count(), 0);
    await sibling.close();
    evidence.checks.push('real cross-tab logout removes the admin view and broadcasts only the neutral invalidation marker');

    checkpoint = 'admin-ledger-states';
    // Omission is an explicit deployment/mounting test, not a fake verified
    // fixture. Restart before destructive integrity cases so readiness does not
    // depend on the synthetic row those existing cases intentionally erase.
    await harness.setLegalLookup(false);
    await open(dpo, harness, '/admin/legal');
    const withoutLookup = (await api(dpo, '/api/v1/admin/capabilities')).body.capabilities;
    assert(withoutLookup.legal_holds_read && withoutLookup.legal_holds_apply && withoutLookup.legal_holds_release &&
      withoutLookup.preservation_requests_create && !withoutLookup.legal_inquiry_lookup);
    assert.equal(await dpo.getByRole('button', { name: localizedText('Attribution'), exact: true }).count(), 0);
    assert.equal((await api(dpo, legalLookup, { method: 'POST', body: {},
      sessionID: (await api(dpo, '/api/v1/users/me')).body.session.id })).status, 404);
    evidence.checks.push('real signer/operator lookup probe before both API replicas, missing/wrong/key-mismatch rejection and explicit fixture-omitted replica restart keeps holds independent while attribution is unmounted');
    await harness.waitForAdminDelivery();
    harness.assertPrivateLogs();
    // These cases deliberately remove signed data and the durable head. Stop
    // the real signer only after delivery, rather than race its fail-closed poll.
    await harness.stopSignerForDestructiveFixtures();
    evidence.checks.push('real signer delivery completes before a verified clean signer retirement for isolated destructive ledger fixtures; all other supervised processes remain health-checked');
    harness.fixture('admin-tamper', { scenario: 'ledger-payload-absent' });
    await open(dpo, harness, '/admin/integrity');
    await dpo.getByLabel(localizedText('Chain'), { exact: true }).selectOption('ledger');
    const tampered = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: localizedText('Start new run'), exact: true }).click();
    const broken = await (await tampered).json();
    assert.equal(broken.verified, false);
    assert.equal(broken.failure_reason, 'payload_absent_without_erasure_record');
    await dpo.getByRole('main').getByRole('alert').waitFor();
    assert(await dpo.getByRole('button', { name: localizedText('Continue verification'), exact: true }).isDisabled());
    harness.fixture('admin-chain-state', { scenario: 'erased' });
    let allErased = 0;
    for (let page = 0; page < 32; page++) {
      const nextProof = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
      await dpo.getByRole('button', { name: localizedText(page === 0 ? 'Start new run' : 'Continue verification'), exact: true }).click();
      const result = await (await nextProof).json();
      assert(result.verified && result.checked > 0 && result.checked === result.erased_checked);
      allErased += result.checked;
      if (result.complete) break;
      assert(page < 31, 'Fixture proof exceeded its bounded page budget');
    }
    assert(allErased > 0);
    await dpo.getByText(localizedText(/without verifying its erased content/)).waitFor();
    harness.fixture('admin-chain-state', { scenario: 'empty' });
    const empty = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: localizedText('Start new run'), exact: true }).click();
    const emptyBody = await (await empty).json();
    assert(emptyBody.verified && emptyBody.complete && emptyBody.checked === 0);
    await dpo.getByText(localizedText('No records checked.'), { exact: true }).waitFor();
    await dpo.getByText(localizedText(/not proof that no activity occurred/)).waitFor();
    harness.fixture('admin-chain-state', { scenario: 'missing-head' });
    const missing = operationResponse(dpo, '/api/v1/admin/ledger/verify', 'GET');
    await dpo.getByRole('button', { name: localizedText('Start new run'), exact: true }).click();
    assert.equal((await missing).status(), 400);
    await dpo.getByRole('main').getByRole('alert').waitFor();
    assert(await dpo.getByRole('button', { name: localizedText('Continue verification'), exact: true }).isDisabled());
    evidence.checks.push('real tampered ledger stops; database-relative erasure annotations never claim content verification, receipt chaining or legal authorization; initialized empty and missing head stay distinct');

    checkpoint = 'admin-final';
    for (const { page, observed } of Object.values(actors)) {
      await assertAdminPrivacy(page, observed, markers);
      assert.equal(observed.downloads, 0);
    }
    assert(harness.originEvidence.admin > 0 && harness.originEvidence.unsafe > 0);
    assert.equal(harness.originEvidence.mismatched, 0);
    assert.equal(harness.originEvidence.referrers, 0);
    harness.assertHealthy();
    harness.assertPrivateLogs();
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
    for (const locale of browserLocales) {
      setBrowserLocale(locale);
      const root = process.env.ADMIN_BROWSER_ARTIFACT_DIR;
      const evidence = await runAdminBrowser({ directory: root ? resolve(root, locale) : undefined });
      console.log(JSON.stringify(evidence, null, 2));
    }
    console.log('Focused real-API admin browser checks and teardown passed');
  } catch (error) {
    console.error(browserFailure(error, checkpoint));
    process.exitCode = 1;
  }
}
