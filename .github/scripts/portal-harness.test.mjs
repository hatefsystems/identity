import assert from 'node:assert/strict';
import { setBrowserLocale } from './browser-localization.mjs';
import childProcess, { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { connect } from 'node:tls';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { chromium } from 'playwright';
import {
  anonymousReclaim,
  assertLocalOrigin,
  browserFailure,
  capturePortalJSON,
  fixtureSecretValues,
  fixtureRouteReferences,
  freePorts,
  integrationTargets,
  integrationInvocation,
  acceptanceLifecycle,
  failureCategories,
  legalCoordinateRequest,
  legalIdempotencyKey,
  legalReferenceRequest,
  lookupProbeFixture,
  portalCleanup,
  portalRoute,
  portalResponseBudget,
  privateLogSummary,
  probeRaceToolchain,
  redactFixtureSecrets,
  replicaFor,
  runPortalIntegrationSuites,
  runPortalIntegrationTarget,
  secretEnvironmentValues,
  startPortalServices,
} from './portal-harness.mjs';
import { identityGoModule, integrationPackages, racePackages, raceToolchainProfile } from './acceptance-report.mjs';
import { decodeQuotedPrintableUTF8, deletionMail, startMailSink } from './portal-mail-sink.mjs';
import { adminAppearance, adminInvocation, adminWorktreeIdentity, observeAdminMarkers, observeLegalPrivacy, observeLegalWrites, observeStatusPatches, reviewAppearance, runAdminBrowser, visibleKeyboardStops } from './web-admin.browser.mjs';
import { clean, destructiveAppearance, keyStorage, newContext, recoveryAction, runPortalBrowser, validatePortal } from './web-portal.browser.mjs';

function testDirectory(prefix) {
  const parent = join(tmpdir(), 'kilo');
  mkdirSync(parent, { recursive: true });
  return mkdtempSync(join(parent, prefix));
}

test('fixture port groups are distinct, released after allocation, and bounded', async () => {
  for (const count of [1, 3, 5]) {
    const ports = await freePorts(count);
    assert.equal(ports.length, count);
    assert.equal(new Set(ports).size, count);
    const listeners = [];
    try {
      for (const port of ports) {
        const listener = net.createServer();
        listeners.push(listener);
        listener.listen(port, '127.0.0.1');
        await once(listener, 'listening');
      }
    } finally {
      await Promise.all(listeners.map((listener) => listener.listening ? new Promise((resolve) => listener.close(resolve)) : undefined));
    }
  }
  for (const count of [0, -1, 9, 1.5]) await assert.rejects(freePorts(count), /Invalid fixture port group/);
});

test('portal harness refuses HTTP, remote, and noncanonical origins', () => {
  assert.equal(assertLocalOrigin('https://localhost:43210').port, '43210');
  for (const value of [
    'http://localhost:43210',
    'https://identity.example.test:43210',
    'https://localhost:43210/',
    'https://localhost:43210/path',
    'https://user@localhost:43210',
    'https://localhost',
  ])
    assert.throws(() => assertLocalOrigin(value));
});

test('ceremony starts and nonce retries stay on A, completions stay on B', () => {
  for (let request = 0; request < 4; request++) {
    for (const flow of ['login', 'register']) {
      assert.equal(replicaFor(`/api/v1/auth/webauthn/${flow}/generate-options`, request), 0);
      assert.equal(replicaFor(`/api/v1/auth/webauthn/${flow}/verify`, request), 1);
    }
    assert.equal(replicaFor('/api/v1/auth/stepup/challenge', request), 0);
    assert.equal(replicaFor('/api/v1/auth/stepup/verify', request), 1);
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim/options', request), 0);
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim', request), 1);
    assert.equal(replicaFor('/api/v1/auth/deletion/reclaim/', request), 1);
    assert.equal(replicaFor('/api/v1/users/me', request), request % 2);
  }
});

test('no-DPoP success exception covers only exact anonymous POST reclaim routes', () => {
  for (const path of ['/api/v1/auth/deletion/reclaim/options', '/api/v1/auth/deletion/reclaim', '/api/v1/auth/deletion/reclaim/']) {
    assert(anonymousReclaim(path, 'POST'));
    assert(!anonymousReclaim(path, 'GET'));
  }
  for (const path of ['/api/v1/users/me', '/api/v1/auth/deletion/reclaim/options/', '/api/v1/auth/deletion/reclaim/unknown', '/api/v1/auth/stepup/verify']) {
    assert(!anonymousReclaim(path, 'POST'));
  }
});

test('portal diagnostics use route templates rather than credential/session IDs', () => {
  assert.equal(
    portalRoute('/api/v1/auth/webauthn/keys/not-a-log-field'),
    '/api/v1/auth/webauthn/keys/{id}'
  );
  assert.equal(
    portalRoute('/api/v1/users/me/sessions/not-a-log-field'),
    '/api/v1/users/me/sessions/{id}'
  );
  assert.equal(portalRoute('/api/v1/users/me'), '/api/v1/users/me');
  assert.equal(portalRoute('/admin/users/private-subject?email=private%40example.test#secret'), '/admin/users/{id}');
  assert.equal(portalRoute('/api/v1/admin/users/private-subject/status?reason=private'), '/api/v1/admin/users/{id}/status');
  assert.equal(portalRoute('/api/v1/admin/ledger/verify?after_seq=123'), '/api/v1/admin/ledger/verify');
  assert.equal(portalRoute('/api/v1/admin/legal-holds/private-request?account_ref=private'), '/api/v1/admin/legal-holds/{hold_id}');
  assert.equal(portalRoute('/api/v1/admin/legal-holds?account_ref=private'), '/api/v1/admin/legal-holds');
  assert.equal(portalRoute('/api/v1/admin/legal-inquiry/lookup?email=private'), '/api/v1/admin/legal-inquiry/lookup');
  assert.equal(portalRoute('/api/v1/admin/preservation-requests'), '/api/v1/admin/preservation-requests');
  assert.equal(portalRoute('/admin/legal?email=private#private'), '/admin/legal');
  assert.equal(portalRoute('/admin/legal/private-reference'), '[redacted-route]');
  assert.equal(portalRoute('/api/v1/admin/unknown/private?token=secret'), '[redacted-route]');
  assert.equal(portalRoute('/admin/unknown/private'), '[redacted-route]');
});

const legalAccount = 'a8c97c4a-81ed-4aef-bc8f-6c572fd53e90';
const legalHoldID = '036bf2b2-e79e-47be-9d04-d456fa53c78b';
const legalOperationID = 'a9a6bd84-8479-48d8-926b-a9e13c52f414';

test('legal probe idempotency support permits only canonical keys on exact create POST routes', () => {
  for (const path of ['/api/v1/admin/legal-holds', '/api/v1/admin/preservation-requests']) {
    assert.equal(legalIdempotencyKey(path, 'POST', legalOperationID), legalOperationID);
    for (const value of ['', null, 1, legalOperationID.toUpperCase(), `{${legalOperationID}}`,
      '00000000-0000-0000-0000-000000000000', `${legalOperationID}\r\nX-Debug: PRIVATE`])
      assert.throws(() => legalIdempotencyKey(path, 'POST', value), /Invalid scoped legal operation key/);
    for (const method of ['GET', 'DELETE', 'PATCH', 'post'])
      assert.throws(() => legalIdempotencyKey(path, method, legalOperationID));
    for (const suffix of ['/', '?', '?account_ref=PRIVATE', '#PRIVATE'])
      assert.throws(() => legalIdempotencyKey(path + suffix, 'POST', legalOperationID));
  }
  for (const path of ['/api/v1/admin/users/lookup', '/api/v1/admin/legal-inquiry/lookup', `/api/v1/admin/legal-holds/${legalHoldID}`])
    assert.throws(() => legalIdempotencyKey(path, 'POST', legalOperationID));
  assert.equal(legalIdempotencyKey('/api/v1/users/me', 'GET', undefined), undefined);
});

test('legal reference privacy exceptions are run-owned typed API requests, never navigation or arbitrary queries', () => {
  const harness = { origin: 'https://localhost:43210', legalReferences: { accounts: new Set([legalAccount]), holds: new Set([legalHoldID]) } };
  const request = (path, method = 'GET', navigation = false) => ({ url: () => harness.origin + path, method: () => method, isNavigationRequest: () => navigation });
  const path = `/api/v1/admin/legal-holds?account_ref=${legalAccount}&status=all&limit=2&offset=0`;
  assert(legalReferenceRequest(request(path), legalAccount, harness));
  assert(legalReferenceRequest(request(`/api/v1/admin/legal-holds/${legalHoldID}`, 'DELETE'), legalHoldID, harness));
  for (const bad of [request(path, 'POST'), request(path, 'GET', true), request(path + '#private'),
    request(path + `&account_ref=${legalAccount}`), request(path + `&reason=${legalAccount}`),
    request(path + '&unknown=x'), request(path + '&status=all'), request(path + '&%zz=x'),
    request(`/api/v1/admin/legal-holds?account_ref=${legalAccount}&status=unknown`),
    request(`/api/v1/admin/legal-holds?account_ref=${legalAccount}&offset=-1`),
    request(`/api/v1/admin/legal-holds?account_ref=${legalAccount}&limit=0`),
    request(`/admin/legal?account_ref=${legalAccount}`), request(`/api/v1/admin/users?account_ref=${legalAccount}`),
    request(`/api/v1/admin/legal-holds/${legalAccount}`, 'DELETE'), request(`/api/v1/admin/legal-holds/${legalHoldID}`, 'GET'),
    request(`/api/v1/admin/legal-holds/${legalHoldID}/`, 'DELETE'), request(`/api/v1/admin/legal-holds/${legalHoldID}?`, 'DELETE')])
    assert(!legalReferenceRequest(bad, bad.url().includes(legalHoldID) ? legalHoldID : legalAccount, harness));
  assert(!legalReferenceRequest(request(path), legalAccount, { ...harness, legalReferences: { accounts: new Set(), holds: new Set() } }));
  assert(!legalReferenceRequest({ ...request(path), url: () => `https://remote.example.test${path}` }, legalAccount, harness));
});

test('response captures share exact audit and legal 4MiB exceptions without widening other routes', async () => {
  for (const [path, method] of [['/api/v1/admin/audit-logs', 'GET'], ['/api/v1/admin/legal-holds', 'GET'], ['/api/v1/admin/legal-inquiry/lookup', 'POST']]) {
    assert.equal(portalResponseBudget(path, method), 4 * 1024 * 1024);
    assert.equal(portalResponseBudget(path + '/', method), 256 * 1024);
    assert.equal(portalResponseBudget(path + '?limit=2', method), 256 * 1024);
    assert.equal(portalResponseBudget(path, method === 'GET' ? 'POST' : 'GET'), 256 * 1024);
  }
  assert.equal(portalResponseBudget('/api/v1/admin/preservation-requests', 'POST'), 256 * 1024);
  assert.equal(portalResponseBudget(`/api/v1/admin/legal-holds/${legalHoldID}`, 'DELETE'), 256 * 1024);
  const capture = (body, limit, headers = {}, signal) => {
    const response = new EventEmitter();
    response.headers = { 'content-type': 'application/json', ...headers };
    const pending = capturePortalJSON(response, limit);
    queueMicrotask(() => {
      if (signal) response.emit(signal, new Error('PRIVATE response failure'));
      for (let offset = 0; offset < body.length; offset += 8192) response.emit('data', Buffer.from(body.slice(offset, offset + 8192)));
      response.emit('end');
    });
    return pending;
  };
  const body = JSON.stringify({ value: 'x'.repeat(270 * 1024) });
  assert.equal((await capture(body, 4 * 1024 * 1024)).value.length, 270 * 1024);
  for (const attempt of [
    () => capture(body, 256 * 1024),
    () => capture('{}', 4 * 1024 * 1024, { 'content-length': String(4 * 1024 * 1024 + 1) }),
    () => capture('{}', 256 * 1024, { 'content-length': 'not-a-length' }),
    () => capture(JSON.stringify({ value: 'x'.repeat(4 * 1024 * 1024) }), 4 * 1024 * 1024),
    () => capture('{"value":', 256 * 1024),
    () => capture('{}', 256 * 1024, { 'content-type': 'text/html' }),
    () => capture('{}', 256 * 1024, {}, 'aborted'),
    () => capture('{}', 256 * 1024, {}, 'error'),
  ]) await assert.rejects(attempt(), (error) => error.message === 'Bounded upstream response capture failed');
});

test('real lookup probe output is private, unique, bounded and canonical before API startup', () => {
  const output = `{"fixture_id":"PRIVATE-LOG","synthetic_account":"PRIVATE-SUBJECT"}\nADMIN_LOOKUP_FIXTURE_ID=${legalHoldID}\n`;
  assert.equal(lookupProbeFixture({ status: 0, stdout: output }), legalHoldID);
  for (const result of [
    { status: 1, stdout: output }, { status: null, stdout: output }, { error: new Error('PRIVATE'), status: 0, stdout: output },
    { status: 0, stdout: '' }, { status: 0, stdout: output + output }, { status: 0, stdout: output + 'x'.repeat(64 * 1024) },
    { status: 0, stdout: `ADMIN_LOOKUP_FIXTURE_ID=${legalHoldID.toUpperCase()}\n` },
    { status: 0, stdout: 'ADMIN_LOOKUP_FIXTURE_ID=00000000-0000-0000-0000-000000000000\n' },
  ]) assert.throws(() => lookupProbeFixture(result), (error) => !/PRIVATE|synthetic_account/.test(error.message));
  const source = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  const signer = source.indexOf("start('Audit signer'");
  const probe = source.indexOf("lookupProbeFixture(spawnSync(legalBinary, ['--operation=lookup-probe']");
  const verified = source.indexOf("fixture('admin-legal-probe'");
  const assigned = source.indexOf('apiEnvironment.ADMIN_LOOKUP_FIXTURE_ID = lookupFixture');
  assert(signer >= 0 && probe > signer && verified > probe && assigned > verified && source.indexOf('startAPIs();') > assigned);
  assert.doesNotMatch(source, /console\.(?:log|error)\([^\n]*(?:rejected|lookupFixture|result\.stdout)/);
});

test('browser failures never print request headers, bodies or locator values', () => {
  const failure = new Error('cookie: PRIVATE-COOKIE dpop: PRIVATE-PROOF grant: PRIVATE-GRANT');
  failure.stack += '\n    at loseResponse (web-portal.browser.mjs:975:34)';
  const message = browserFailure(failure, 'uncertain-recovery');
  assert.match(message, /uncertain-recovery.*web-portal\.browser\.mjs:975:34/);
  assert.doesNotMatch(message, /PRIVATE-|cookie:|grant:|dpop:/);
  assert.match(browserFailure(failure, 'SECRET USER VALUE'), /during unknown/);
  failure.stack += '\n    at validateAdmin (web-admin.browser.mjs:40:9)';
  assert.match(browserFailure(failure, 'admin-uncertain'), /admin-uncertain/);
  const helperFailure = { name: 'AssertionError', stack: 'PRIVATE cookie=secret\n at chooseLanguage (browser-localization.mjs:187:9)\n at profileAndSessions (web-portal.browser.mjs:602:3)' };
  const helperMessage = browserFailure(helperFailure, 'profile-sessions');
  assert.match(helperMessage, /at browser-localization\.mjs:187:9/);
  assert.doesNotMatch(helperMessage, /PRIVATE|cookie=|secret/);
});

test('portal cleanup shares one promise and waits for every resource in reverse order', async () => {
  const calls = [];
  let resume, entered;
  const waiting = new Promise((resolve) => { resume = resolve; });
  const started = new Promise((resolve) => { entered = resolve; });
  const resources = [() => calls.push('first')];
  const close = portalCleanup(resources);
  resources.push(async () => {
    calls.push('last-start');
    entered();
    assert.equal(close(), pending, 'Reentrant close did not share the pending result');
    await waiting;
    calls.push('last-end');
  });
  const pending = close();
  assert.equal(close(), pending);
  await started;
  assert.deepEqual(calls, ['last-start']);
  resume();
  assert.deepEqual(await pending, { completed: true });
  assert.equal(close(), pending);
  assert.deepEqual(await close(), { completed: true });
  assert.deepEqual(calls, ['last-start', 'last-end', 'first']);
  assert.equal(resources.length, 0);
});

test('portal cleanup rejects only after all sync and async disposers run and never forgets failure', async () => {
  const calls = [];
  const close = portalCleanup([
    () => calls.push('remaining-resource'),
    async () => { calls.push('async-failure'); throw new Error('PRIVATE-PAYLOAD'); },
    () => { calls.push('sync-failure'); throw new Error('PRIVATE-CREDENTIAL'); },
  ]);
  const pending = close();
  let failure;
  await assert.rejects(pending, (error) => {
    failure = error;
    assert.equal(error.message, 'Disposable portal cleanup did not complete; sensitive exception details suppressed.');
    assert.equal(error.cause, undefined);
    return true;
  });
  assert.equal(close(), pending);
  await assert.rejects(close(), (error) => error === failure);
  assert.deepEqual(calls, ['sync-failure', 'async-failure', 'remaining-resource']);
});

test('portal key storage and clean reject an extra private object store beside an otherwise valid key', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { crv, kty, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const stores = new Map([['keys', [{ privateKey: pair.privateKey, publicJwk: { crv, kty, x, y } }]]]);
  let closed = 0;
  const request = (result) => {
    const pending = { result };
    queueMicrotask(() => pending.onsuccess());
    return pending;
  };
  const database = {
    get objectStoreNames() { return [...stores.keys()]; },
    transaction(name, mode) {
      assert.equal(name, 'keys');
      assert.equal(mode, 'readonly');
      return { objectStore: (store) => ({ getAll: () => request(stores.get(store)) }) };
    },
    close() { closed++; },
  };
  const page = {
    evaluate: async (callback) => structuredClone(await runInNewContext(`(${callback})()`, {
      indexedDB: { databases: async () => [{ name: 'hatef-portal-dpop' }], open: () => request(database) },
      crypto: webcrypto, CryptoKey: pair.privateKey.constructor, TextEncoder,
      localStorage: { length: 0 }, sessionStorage: { length: 0 }, __portalCsp: [], __portalBroadcasts: [],
    })),
    locator: () => ({ evaluateAll: async (callback) => callback([]) }),
  };
  const observed = { pending: [], failures: [] };
  assert.equal((await keyStorage(page)).localEmpty, true);
  await clean(page, observed);
  stores.set('private-drafts', [{ reason: 'PRIVATE-REASON', payload: 'PRIVATE-PAYLOAD' }]);
  for (const inspect of [() => keyStorage(page), () => clean(page, observed)]) {
    await assert.rejects(inspect(), (error) => {
      assert.equal(error.message, 'Unexpected persistent portal object store');
      assert.doesNotMatch(error.message, /PRIVATE-|private-drafts/);
      return true;
    });
  }
  assert.equal(closed, 4, 'Every accepted or rejected storage inspection must close its connection');
});

test('admin appearance rejects undersized pointer targets, weak contrast and invisible or clipped keyboard focus', () => {
  const inspect = ({ checkbox = false, width = 44, labelWidth = 44, labelled = true, focused = true,
    color = 'rgb(0, 0, 0)', shadow = 'rgb(0, 0, 0) 0px 0px 0px 2px', left = 0, focusedOnly = false,
    forcedColors = false, outlineStyle = 'none', outlineWidth = '0px', forcedColorAdjust = 'auto' } = {}) => {
    const style = {
      color, backgroundColor: 'rgb(255, 255, 255)', fontSize: '16px', fontWeight: '400',
      boxShadow: shadow, outlineStyle, outlineWidth, outlineColor: 'rgb(0, 0, 0)', forcedColorAdjust,
    };
    const element = (size) => ({
      parentElement: null,
      getClientRects: () => [{}], checkVisibility: () => true, closest: () => null,
      matches: (selector) => selector === ':focus-visible' ? focused :
        checkbox && ['input[type=checkbox]', 'input, select, textarea'].includes(selector),
      getBoundingClientRect: () => ({ left, right: left + size, top: 0, bottom: 44, width: size, height: 44 }),
    });
    const control = element(checkbox ? 20 : width);
    control.labels = labelled ? [element(labelWidth)] : [];
    let text = { parentElement: control, textContent: 'PRIVATE-FIXTURE-TEXT' };
    return structuredClone(runInNewContext(`(${adminAppearance})({ focusedOnly, forcedColors })`, {
      focusedOnly, forcedColors, innerWidth: 320, innerHeight: 256, NodeFilter: { SHOW_TEXT: 4 },
      getComputedStyle: () => style,
      document: {
        getAnimations: () => [],
        querySelector: () => null, querySelectorAll: () => [control], activeElement: control,
        documentElement: { scrollWidth: 320 }, body: {},
        createTreeWalker: () => ({ nextNode: () => { const next = text; text = null; return next; } }),
      },
    }));
  };
  assert.deepEqual(inspect(), []);
  assert.deepEqual(inspect({ checkbox: true }), [], 'A 20px checkbox may use its 44px clickable label');
  for (const options of [{ width: 43 }, { checkbox: true, labelWidth: 43 }])
    assert(inspect(options).includes('Admin interaction target is below 44px'));
  assert(inspect({ checkbox: true, labelled: false }).includes('Admin checkbox lacks a visible associated label'));
  assert(inspect({ color: 'rgb(200, 200, 200)' }).includes('Admin text contrast is below its readable-size threshold'));
  assert.deepEqual(inspect({ focusedOnly: true }), []);
  assert(inspect({ focusedOnly: true, forcedColors: true }).includes('Admin keyboard target lacks a 2px, 3:1 focus indicator'));
  assert.deepEqual(inspect({ focusedOnly: true, forcedColors: true, shadow: 'none', outlineStyle: 'solid', outlineWidth: '2px' }), []);
  assert(inspect({ forcedColors: true, forcedColorAdjust: 'none' }).includes('Admin control suppresses forced colors'));
  for (const options of [{ focused: false }, { shadow: 'none' }, { shadow: 'rgb(200, 200, 200) 0px 0px 0px 2px' }, { left: -2 }]) {
    const failures = inspect({ ...options, focusedOnly: true });
    assert(failures.length > 0);
    assert.doesNotMatch(JSON.stringify(failures), /PRIVATE-/);
  }
});

test('review keyboard inventory excludes hidden, disabled, inert, collapsed-details and negative-tabindex targets only', () => {
  const visible = (change = {}) => ({ tabIndex: 0, matches: () => false, closest: () => null,
    checkVisibility: () => true, getClientRects: () => [{}], parentElement: null, ...change });
  const summary = visible();
  const details = { localName: 'details', open: false, parentElement: null, querySelector: () => ({ contains: (node) => node === summary }) };
  summary.parentElement = details;
  const nodes = [visible(), visible({ tabIndex: -1 }), visible({ matches: () => true }), visible({ closest: () => ({}) }),
    visible({ checkVisibility: () => false }), visible({ getClientRects: () => [] }), summary, visible({ parentElement: details })];
  assert.deepEqual(visibleKeyboardStops(nodes), [0, 6]);
  details.open = true;
  assert.deepEqual(visibleKeyboardStops(nodes), [0, 6, 7]);
});

test('long review requires a persistent localized title/cancel footer and independently scrollable body', () => {
  const inspect = ({ locale = 'en', bodyHeight = 128, overflow = 'auto', movingHeader = false, cancelCount = 1, layout = 'review' } = {}) => {
    const body = { scrollTop: 0, scrollHeight: 400, clientHeight: bodyHeight,
      getBoundingClientRect: () => ({ top: 64, bottom: 64 + bodyHeight, height: bodyHeight }) };
    const header = { querySelector: () => ({}), getBoundingClientRect: () => ({ top: movingHeader ? body.scrollTop : 0, bottom: 64 }) };
    const footer = { getBoundingClientRect: () => ({ top: 192, bottom: 256 }),
      querySelectorAll: () => Array.from({ length: cancelCount }, () => ({ textContent: locale === 'en' ? 'Cancel' : 'لغو' })) };
    const dialog = { getAttribute: () => layout, querySelectorAll: () => [body], querySelector: (selector) => selector === 'header' ? header : footer };
    return structuredClone(runInNewContext(`(${reviewAppearance})(dialog)`, {
      dialog, innerHeight: 256, getComputedStyle: () => ({ overflowY: overflow }), document: { documentElement: { lang: locale } },
    }));
  };
  for (const locale of ['en', 'fa-IR']) assert.deepEqual(inspect({ locale }), []);
  for (const options of [{ bodyHeight: 0 }, { bodyHeight: 200 }, { overflow: 'visible' }, { movingHeader: true },
    { cancelCount: 0 }, { cancelCount: 2 }, { layout: 'default' }]) assert(inspect(options).length > 0);
});

test('portal recovery acceptance uses exact known-zero, known-positive and unknown actions in both locales', async () => {
  try {
    for (const locale of ['en', 'fa-IR']) for (const remaining of [0, 10, null]) {
      setBrowserLocale(locale);
      const english = remaining === null ? 'Generate or replace recovery codes' : remaining === 0 ? 'Generate new recovery codes' : 'Replace recovery codes';
      const persian = remaining === null ? 'تولید یا جایگزینی کدهای بازیابی' : remaining === 0 ? 'تولید کدهای بازیابی جدید' : 'جایگزینی کدهای بازیابی';
      const action = { count: async () => 1 };
      const page = {
        getByTestId: () => ({ locator: () => ({ count: async () => remaining === null ? 0 : 1,
          textContent: async () => new Intl.NumberFormat(locale).format(remaining) }) }),
        getByRole: (role, options) => {
          assert.equal(role, 'button'); assert.equal(options.exact, true);
          if (locale === 'en') assert.equal(options.name, english); else assert.match(persian, options.name);
          return action;
        },
      };
      assert.equal(await recoveryAction(page), action);
    }
  } finally { setBrowserLocale('en'); }
});

test('enabled destructive contrast composites alpha and opacity, requires essential focus and separates forced colors', () => {
  const inspect = ({ backgroundColor = 'rgb(185, 28, 28)', color = 'rgb(255, 255, 255)', opacity = '1',
    parentColor = 'rgba(255, 255, 255, 0)', parentOpacity = '1', rootColor = 'rgb(255, 255, 255)', focused = true, disabled = false,
    visible = true, shadow = 'rgb(255, 255, 255) 0px 0px 0px 2px, rgb(0, 0, 0) 0px 0px 0px 4px',
    left = 0, focusVisible = false, forcedColors = false, actualForcedColors = forcedColors,
    outlineWidth = '0px', outlineStyle = 'none', outlineColor = 'rgb(0, 0, 0)', forcedColorAdjust = 'auto',
    backgroundImage = 'none' } = {}) => {
    const base = { backgroundImage: 'none', backgroundColor: rootColor, opacity: '1' };
    const root = { parentElement: null, style: base };
    const parent = { parentElement: root, style: { ...base, backgroundColor: parentColor, opacity: parentOpacity } };
    const element = {
      parentElement: parent, disabled,
      style: { ...base, backgroundColor, color, opacity, boxShadow: shadow,
        outlineWidth, outlineStyle, outlineColor, outlineOffset: '2px', forcedColorAdjust, backgroundImage },
      textContent: 'PRIVATE-FIXTURE-CONTROL',
      checkVisibility: () => visible, matches: () => focused,
      getBoundingClientRect: () => ({ left, right: left + 150, top: 0, bottom: 44 }),
    };
    return structuredClone(runInNewContext(`(${destructiveAppearance})(element, options)`, {
      element, options: { focusVisible, forcedColors }, getComputedStyle: (node) => node.style,
      document: { activeElement: focused ? element : parent }, innerWidth: 320, innerHeight: 256,
      matchMedia: () => ({ matches: actualForcedColors }),
    }));
  };
  assert.deepEqual(inspect(), []);
  assert.deepEqual(inspect({ focusVisible: true }), []);
  assert.deepEqual(inspect({ backgroundColor: 'rgba(185, 28, 28, 0.9)' }), [], 'Hover alpha must be composited with its actual backdrop');
  assert.deepEqual(inspect({ rootColor: 'rgb(2, 6, 23)', backgroundColor: 'rgb(127, 29, 29)' }), [], 'Dark button fill is not an essential boundary when its text identifies the action');
  for (const options of [
    { backgroundColor: 'rgb(239, 68, 68)' }, { backgroundColor: 'rgba(185, 28, 28, 0.4)' },
    { opacity: '0.5' }, { parentOpacity: '0.5' }, { color: 'rgba(255, 255, 255, 0.3)' },
  ]) assert(inspect(options).includes('Destructive-state text contrast is below 4.5:1'));
  for (const options of [
    { focused: false }, { shadow: 'none' },
    { shadow: 'rgb(220, 220, 220) 0px 0px 0px 2px' },
    { shadow: 'rgb(255, 255, 255) 0px 0px 0px 3px, rgb(0, 0, 0) 0px 0px 0px 4px' },
    { left: -2 },
  ]) assert(inspect({ ...options, focusVisible: true }).length > 0);
  assert(inspect({ disabled: true }).includes('Destructive-state control is not visible and enabled'));
  assert(inspect({ visible: false }).includes('Destructive-state control is not visible and enabled'));
  assert(inspect({ forcedColors: true, actualForcedColors: false }).includes('Destructive-state palette does not match the requested color mode'));
  assert(inspect({ forcedColors: true, forcedColorAdjust: 'none' }).includes('Destructive-state control suppresses forced colors'));
  assert(inspect({ forcedColors: true, focusVisible: true }).includes('Destructive-state focus indicator is below 3:1 or 2px'), 'Forced-color box shadows must never prove native focus');
  assert.deepEqual(inspect({ forcedColors: true, focusVisible: true, shadow: 'none',
    outlineStyle: 'solid', outlineWidth: '2px' }), []);
  assert.throws(() => inspect({ backgroundImage: 'linear-gradient(red, white)' }), /Unmeasured destructive-state background image/);
  for (const color of ['rgb(NaN, 255, 255)', 'rgba(255, 255, 255, 2)', 'PRIVATE-COLOR'])
    assert.throws(() => inspect({ color }), /(?:Invalid|Unsupported) computed destructive-state color/);
  assert.doesNotMatch(JSON.stringify(inspect({ color: 'rgb(200, 200, 200)', focused: false, focusVisible: true })), /PRIVATE-/);
});

test('portal browser cleanup attempts browser close even after a context rejects', async (t) => {
  const calls = [];
  const context = {
    setDefaultTimeout() {}, setDefaultNavigationTimeout() {}, async addInitScript() {}, on() {},
    async newPage() { throw new Error('Stop before any browser or API work'); },
    async close() { calls.push('context'); throw new Error('PRIVATE-CLEANUP'); },
  };
  t.mock.method(chromium, 'launch', async () => ({
    newContext: async () => context,
    close: async () => { calls.push('browser'); },
  }));
  await assert.rejects(validatePortal({ tlsSPKI: 'fixture', fixture: () => ({}) }), /Disposable portal cleanup did not complete/);
  assert.deepEqual(calls, ['context', 'browser']);
});

test('portal evidence invalidates stale success and waits for affirmative teardown before publishing', async () => {
  const directory = testDirectory('portal-evidence-test-');
  const path = join(directory, 'portal-evidence.json');
  let resume, entered;
  const waiting = new Promise((resolve) => { resume = resolve; });
  const closing = new Promise((resolve) => { entered = resolve; });
  let closes = 0, released = false;
  try {
    writeFileSync(path, '{"status":"passed","checks":["stale"]}');
    const pending = runPortalBrowser({
      directory,
      start: async () => {
        assert.equal(existsSync(path), false);
        return { secrets: [], diagnostics() {}, close: async () => {
          closes++;
          entered();
          await waiting;
          return { completed: true };
        } };
      },
      validate: async () => ({ checks: ['current assertions'], manualGates: ['Native/manual checks remain'] }),
      guard: () => () => { released = true; },
    });
    await closing;
    assert.equal(existsSync(path), false, 'Portal success was published while teardown was pending');
    resume();
    const report = await pending;
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), report);
    assert.equal(report.status, 'passed');
    assert.equal(report.exitStatus, 0);
    assert.equal(report.teardown, 'completed');
    assert.equal(closes, 1);
    assert.equal(released, true);
  } finally { resume(); rmSync(directory, { recursive: true, force: true }); }
});

test('portal evidence never certifies startup, assertion, cleanup, callback or private-data failure', async (t) => {
  for (const kind of ['startup', 'assertion', 'cleanup', 'unconfirmed-cleanup', 'callback', 'private-evidence']) {
    await t.test(kind, async () => {
      const directory = testDirectory('portal-evidence-test-');
      const path = join(directory, 'portal-evidence.json');
      let interrupt, closes = 0, released = false;
      try {
        writeFileSync(path, '{"status":"passed"}');
        await assert.rejects(runPortalBrowser({
          directory,
          start: async () => {
            if (kind === 'startup') throw new Error('PRIVATE-FAILURE');
            return { secrets: ['PRIVATE-FAILURE'], diagnostics() {}, close: async () => {
              closes++;
              if (kind === 'cleanup') throw new Error('PRIVATE-FAILURE');
              return kind === 'unconfirmed-cleanup' ? undefined : { completed: true };
            } };
          },
          validate: async () => {
            if (kind === 'assertion') throw new Error('PRIVATE-FAILURE');
            if (kind === 'callback') await interrupt();
            return { checks: [kind === 'private-evidence' ? 'PRIVATE-FAILURE' : 'current assertions'] };
          },
          guard: (callback) => { interrupt = callback; return () => { released = true; }; },
        }));
        assert.equal(existsSync(path), false, 'A failed portal run left success evidence');
        assert.equal(closes, kind === 'startup' ? 0 : 1);
        assert.equal(released, kind !== 'startup');
      } finally { rmSync(directory, { recursive: true, force: true }); }
    });
  }
});

function mockPortalDocker(t, { failCleanup, failCreate, failStart, internalNullBindings = false } = {}) {
  const state = { created: [], started: [], removed: [], reservedPorts: 0, releasedPorts: 0, ownershipViolation: false, rejectedName: null, executions: [], fetches: 0, internal: false };
  const owned = new Set();
  const bindings = new Map();
  const names = new Map(), labels = new Map();
  let network;
  const result = (status = 0, stdout = '') => ({ status, stdout, stderr: status ? 'PRIVATE Docker diagnostic' : '' });
  t.mock.method(net, 'createServer', () => {
    const server = new EventEmitter();
    let port;
    server.listen = (requested, host) => {
      assert.equal(requested, 0);
      assert.equal(host, '127.0.0.1');
      port = 20_000 + ++state.reservedPorts;
      queueMicrotask(() => server.emit('listening'));
    };
    server.address = () => ({ port });
    server.close = (done) => { state.releasedPorts++; queueMicrotask(done); };
    return server;
  });
  t.mock.method(childProcess, 'spawnSync', (command, args, options) => {
    if (state.toolchainProbe && ['cmd.exe', 'go', 'gcc'].includes(command)) return state.toolchainProbe(command, args, options);
    assert.equal(command, 'docker', 'Unexpected process in mocked service test');
    if (args[0] === 'network' && args[1] === 'create') {
      network = args.at(-1);
      state.internal = args.includes('--internal');
      assert.match(network, /^portal-browser-[a-f0-9]{32}$/);
      if (state.internal) {
        assert(args.includes('--subnet'), 'Static registration peers require an explicit Docker subnet');
        const subnet = args[args.indexOf('--subnet') + 1];
        assert.match(subnet, /^10\.(?:1[2-8][0-9]|19[01])\.\d{1,3}\.0\/24$/);
        state.subnet = subnet;
      } else assert(!args.includes('--subnet'), 'Ordinary suites keep Docker pool allocation');
      const id = 'f'.repeat(64);
      names.set(id, network);
      labels.set(id, { 'ldp.run': network.slice('portal-browser-'.length) });
      owned.add(id);
      return result(0, id);
    }
    if (args[0] === 'run' || args[0] === 'create') {
      const name = args[args.indexOf('--name') + 1];
      const kind = name.split('-').at(-1);
      assert.equal(args[args.indexOf('--network') + 1], network);
      assert(args.includes(`ldp.run=${network.slice('portal-browser-'.length)}`));
      assert(args.includes(name === 'admin-test-nats' ? 'ldp.task=6.3' : 'ldp.task=7.5'));
      const ports = {};
      for (let index = 0; index < args.length; index++) {
        if (args[index] !== '--publish') continue;
        const match = args[index + 1].match(/^127\.0\.0\.1:(\d*):(\d+)$/);
        assert(match, 'A disposable port was not bound to loopback');
        ports[match[2]] = { requested: match[1], actual: Number(match[1]) || Number(match[2]) + 10_000 };
      }
      if (kind === failCreate) { state.rejectedName = name; return result(125); }
      const id = String(state.created.length + 1).padStart(64, '0');
      names.set(id, name);
      labels.set(id, { 'ldp.run': network.slice('portal-browser-'.length) });
      owned.add(id);
      bindings.set(id, ports);
      state.created.push({ id: name, kind, operation: args[0], ports });
      return result(0, id);
    }
    if (args[0] === 'start') {
      const id = args[1];
      assert(owned.has(id));
      if (names.get(id).split('-').at(-1) === failStart) return result(125);
      state.started.push(names.get(id));
      return result();
    }
    if (args[0] === 'restart') {
      const id = [...names].find(([id, name]) => id === args[1] || name === args[1])?.[0];
      assert(owned.has(id));
      for (const binding of Object.values(bindings.get(id))) {
        if (!binding.requested) binding.actual++;
      }
      return result();
    }
    if (args[0] === 'inspect' || (args[0] === 'network' && args[1] === 'inspect')) {
      const id = [...names].find(([id, name]) => id === args.at(-1) || name === args.at(-1))?.[0];
      assert(owned.has(id));
      if (args[0] === 'network') return result(0, JSON.stringify([{ Id: id, Labels: labels.get(id) }]));
      const Ports = internalNullBindings ? Object.fromEntries([5432, 6379, 4222, 8222].map((port) => [`${port}/tcp`, null])) : Object.fromEntries(Object.entries(bindings.get(id)).map(([port, binding]) =>
        [`${port}/tcp`, [{ HostIp: '127.0.0.1', HostPort: String(binding.actual) }]]));
      return result(0, JSON.stringify([{ Id: id, Config: { Labels: labels.get(id) }, NetworkSettings: { Ports } }]));
    }
    if ((args[0] === 'container' || args[0] === 'network') && args[1] === 'ls') return result(0, [...owned].filter((id) => args[0] === 'network' ? names.get(id) === network : names.get(id) !== network).join('\n'));
    if (args[0] === 'exec') { assert([...names].some(([id, name]) => owned.has(id) && name === args[1])); state.executions.push(args); return result(0, 'PONG'); }
    if (args[0] === 'rm' || (args[0] === 'network' && args[1] === 'rm')) {
      const id = args.at(-1);
      const kind = args[0] === 'network' ? 'network' : names.get(id).split('-').at(-1);
      state.removed.push(kind);
      if (!owned.has(id)) state.ownershipViolation = true;
      if (kind !== failCleanup) owned.delete(id);
      return result(kind === failCleanup ? 1 : 0);
    }
    throw new Error('Unexpected mocked Docker operation');
  });
  t.mock.method(globalThis, 'fetch', async () => { state.fetches++; return { ok: true }; });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return state;
}

test('internal browser services tolerate null Docker bindings and expose only private handles', async (t) => {
  const state = mockPortalDocker(t, { internalNullBindings: true });
  const services = await startPortalServices({ internal: true });
  try {
    assert.equal(state.internal, true);
    assert(state.subnet, 'Internal service creation must declare its static-IP pool');
    assert.equal(services.environment, null);
    assert.equal(state.fetches, 0);
    assert(state.created.every(({ ports }) => Object.keys(ports).length === 0));
    for (const [kind, peer] of Object.entries(services.privateServices)) {
      assert.match(peer.id, /^[a-f0-9]{64}$/);
      assert.equal(peer.hostname, `portal-browser-${services.runID}-${kind}`);
    }
    assert(state.executions.some((args) => args.includes('/bin/busybox') && args.includes('http://127.0.0.1:8222/healthz?js-enabled-only=true')));
    assert.equal(state.reservedPorts, 0);
  } finally { await services.close(); }
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(state.ownershipViolation, false);
});

test('internal startup failure removes only its created private services with fixed diagnostics', async (t) => {
  const state = mockPortalDocker(t, { internalNullBindings: true, failStart: 'nats' });
  await assert.rejects(startPortalServices({ internal: true }), (error) => !error.message.includes('PRIVATE'));
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(state.ownershipViolation, false);
  assert.equal(state.reservedPorts, 0);
});

test('internal cleanup failure attempts all owned disposers without claiming success', async (t) => {
  const state = mockPortalDocker(t, { internalNullBindings: true, failCleanup: 'redis' });
  const services = await startPortalServices({ internal: true });
  await assert.rejects(services.close(), /Disposable portal cleanup did not complete/);
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(state.ownershipViolation, false);
});

function mockIntegrationRunner(t, { failAt, hang = false, startError = false, output, exit = 0 } = {}) {
  const state = { children: [], active: 0, maximumActive: 0, terminated: [], messages: [] };
  const originalSpawnSync = childProcess.spawnSync;
  const close = (child, code, signal = null) => {
    child.exitCode = code;
    child.signalCode = signal;
    child.emit('exit', code, signal);
    state.active--;
    child.emit('close', code, signal);
  };
  t.mock.method(console, 'log', (message) => state.messages.push(message));
  t.mock.method(childProcess, 'spawn', (command, args, options) => {
    assert.equal(command, process.execPath);
    assert.match(args[0], /[\\/]nx[\\/]dist[\\/]bin[\\/]nx\.js$/);
    const race = args[1] === 'exec';
    if (race) {
      assert.deepEqual(args.slice(1, 6), ['exec', '-p', 'schemas', '--', 'go']);
      assert.deepEqual(args.slice(8, -1), ['test', '-json', '-tags=integration', '-race', '-count=1', '-p=1', '-timeout=20m']);
      assert(racePackages.includes(args.at(-1)));
      assert.equal(options.env.CGO_ENABLED, '1');
    } else {
      assert.equal(args[1], 'run');
      assert.deepEqual(args.slice(3), ['--skipNxCache', '--outputStyle=stream-without-prefixes']);
    }
    assert.equal(options.env.NX_DAEMON, 'false');
    assert.equal(options.env.NX_ISOLATE_PLUGINS, 'false');
    assert.equal(options.env.CI, 'true');
    assert.equal(options.env.GOFLAGS, '-v');
    assert.equal(options.env.REQUIRE_LEGAL_WORKFLOW_INTEGRATION, '1');
    assert.equal(options.env.REQUIRE_PORTAL_INTEGRATION, '1');
    assert.equal(options.env.REQUIRE_GRPC_INTEGRATION, '1');
    assert.equal(options.env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.equal(options.detached, true);
    const child = Object.assign(new EventEmitter(), {
      pid: 100_000 + state.children.length, stdout: new EventEmitter(), stderr: new EventEmitter(),
      exitCode: null, signalCode: null, target: race ? `identity-api:${args.at(-1)}` : args[2], options,
      kill(signal) { state.terminated.push(signal); queueMicrotask(() => close(child, null, signal)); return true; },
    });
    state.children.push(child);
    state.maximumActive = Math.max(state.maximumActive, ++state.active);
    if (!hang) queueMicrotask(() => {
      if (startError) {
        child.emit('error', new Error('PRIVATE process error'));
        close(child, null);
        return;
      }
      if (output) output(child);
      else if (race) {
        const name = `${identityGoModule}/${args.at(-1).slice(2)}`;
        for (const event of [{ Action: 'start', Package: name }, { Action: 'pass', Package: name, Test: 'TestOwnedFixture' }, { Action: 'pass', Package: name }]) child.stdout.emit('data', JSON.stringify(event) + '\n');
      }
      else {
        child.stdout.emit('data', '--- PA');
        child.stderr.emit('data', 'PRIVATE stderr diagnostic\n');
        child.emit('exit', 0, null);
        const packages = integrationPackages[child.target.slice('identity-api:'.length)];
        child.stdout.emit('data', `SS: TestOwnedFixture (0.01s)\nok ${identityGoModule}/${packages[0]}\t0.01s\n`);
        for (const name of packages.slice(1)) child.stdout.emit('data', `--- PASS: TestOwnedFixture (0.01s)\nok ${identityGoModule}/${name}\t0.01s\n`);
      }
      close(child, state.children.length === failAt ? 130 : exit);
    });
    return child;
  });
  if (hang) t.mock.method(childProcess, 'spawnSync', (command, args, options) => {
    if (command !== 'taskkill.exe') return originalSpawnSync(command, args, options);
    const child = state.children.find((candidate) => String(candidate.pid) === args[1]);
    assert(child, 'Teardown targeted a process outside the owned runner');
    assert.deepEqual(args, ['/PID', String(child.pid), '/T', '/F']);
    assert.equal(options.stdio, 'ignore');
    assert.equal(options.timeout, 10_000);
    state.terminated.push('owned-tree');
    queueMicrotask(() => close(child, 1));
    return { status: 0 };
  });
  if (hang) {
    const originalKill = process.kill;
    t.mock.method(process, 'kill', (pid, signal) => {
      const child = state.children.find((candidate) => -candidate.pid === pid);
      if (!child) return originalKill(pid, signal);
      if (state.active === 0) throw Object.assign(new Error('Owned group is gone'), { code: 'ESRCH' });
      return child.kill(signal);
    });
  }
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return state;
}

test('integration runner preserves the Windows Go cache location but excludes inherited credentials', async (t) => {
  const previous = { LOCALAPPDATA: process.env.LOCALAPPDATA, DATABASE_URL: process.env.DATABASE_URL };
  process.env.LOCALAPPDATA = 'fixture-local-app-data';
  process.env.DATABASE_URL = 'PRIVATE inherited database';
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  const state = mockIntegrationRunner(t);
  const result = await runPortalIntegrationTarget(integrationTargets[0], { DATABASE_URL: 'PRIVATE owned database' });
  assert.equal(state.children[0].options.env.LOCALAPPDATA, 'fixture-local-app-data');
  assert.equal(state.children[0].options.env.DATABASE_URL, 'PRIVATE owned database');
   assert.equal(result.packages, integrationPackages[integrationTargets[0]].length);
   assert.equal(result.tests, result.packages);
   assert.equal(result.failed, 0);
   assert.equal(result.skipped, 0);
  assert.doesNotMatch(state.messages.join(''), /PRIVATE|database|app-data|stderr diagnostic/);
});

const fixtureIdentity = { revision: 'a'.repeat(40), source: 'b'.repeat(64), generated: Object.fromEntries(['apps/identity-api/internal/db', 'libs/schemas/gen/go', 'libs/schemas/gen/ts'].map((path) => [path, { files: 1, sha256: 'c'.repeat(64) }])), runId: 'local', runAttempt: '1' };
const identify = async () => fixtureIdentity;
const fixtureToolchain = { schema: 1, profile: raceToolchainProfile,
  go: { GOOS: 'linux', GOHOSTOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '1', GOVERSION: 'go1.26.5' },
  compiler: { name: 'gcc', version: '12.2.0', target: 'x86_64-linux-gnu' } };

function mockToolchainProbes(t, { go = fixtureToolchain.go, goOutput = JSON.stringify(go),
  version = 'gcc (PRIVATE build host /private/path) 12.2.0\nCopyright (C) Free Software Foundation\n',
  target = 'x86_64-linux-gnu\n', result = {}, afterProbe, docker } = {}) {
  const previous = childProcess.spawnSync, calls = [];
  const commands = ['go env -json GOOS GOHOSTOS GOARCH CGO_ENABLED GOVERSION', 'gcc --version', 'gcc -dumpmachine'];
  const run = (command, args, options) => {
    if (!['cmd.exe', 'go', 'gcc'].includes(command)) return previous(command, args, options);
    const expected = commands[calls.length];
    assert(expected, 'Unexpected additional toolchain command');
    if (process.platform === 'win32') {
      assert.equal(command, 'cmd.exe');
      assert.deepEqual(args, ['/d', '/s', '/c', expected]);
      assert.equal(options.windowsVerbatimArguments, true);
    } else {
      assert.equal(command, expected.split(' ')[0]);
      assert.deepEqual(args, expected.split(' ').slice(1));
    }
    assert.equal(options.shell, false);
    assert.equal(options.maxBuffer, 16 * 1024);
    assert(options.timeout > 0 && options.timeout <= 10_000);
    assert.equal(options.env.CGO_ENABLED, '1');
    for (const key of ['GOOS', 'GOHOSTOS', 'GOARCH', 'GOVERSION', 'CC', 'GO', 'GCC', 'RACE_TOOLCHAIN_VERIFIED', 'DATABASE_URL', 'NODE_TLS_REJECT_UNAUTHORIZED']) assert.equal(options.env[key], undefined);
    const stdout = [goOutput, version, target][calls.length];
    calls.push({ command, args, options });
    afterProbe?.(calls.length);
    return { status: 0, signal: null, stdout, stderr: '', ...result };
  };
  if (docker) docker.toolchainProbe = run;
  else t.mock.method(childProcess, 'spawnSync', run);
  syncBuiltinESMExports();
  t.after(() => { if (docker) docker.toolchainProbe = undefined; else t.mock.restoreAll(); syncBuiltinESMExports(); });
  return calls;
}

test('actual Linux Go/GCC proof works under both Windows and Linux Node without an OS bypass', async (t) => {
  for (const platform of ['win32', 'linux']) await t.test(platform, async (t) => {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { ...descriptor, value: platform });
    t.after(() => Object.defineProperty(process, 'platform', descriptor));
    const calls = mockToolchainProbes(t);
    const lifecycle = acceptanceLifecycle();
    try {
      assert.equal(process.platform, platform);
      const proof = await probeRaceToolchain(lifecycle);
      assert.equal(process.platform, platform);
      assert.deepEqual(proof, fixtureToolchain);
      assert.equal(calls.length, 3);
      assert.doesNotMatch(JSON.stringify(proof), /PRIVATE|private|path|host\//);
    } finally { lifecycle.release(); }
  });
});

test('Windows Node publishes race proof only alongside exact executed JSON tests and verified teardown', async (t) => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...descriptor, value: 'win32' });
  t.after(() => Object.defineProperty(process, 'platform', descriptor));
  const docker = mockPortalDocker(t);
  const calls = mockToolchainProbes(t, { docker });
  const state = mockIntegrationRunner(t);
  const directory = mkdtempSync(join(tmpdir(), 'kilo', 'race-toolchain-report-'));
  try {
    const report = await runPortalIntegrationSuites({ identify, directory, invocation: integrationInvocation(['--integration-race-package=./internal/mfa']) });
    assert.equal(process.platform, 'win32');
    assert.equal(calls.length, 3);
    assert.deepEqual(report.toolchain, fixtureToolchain);
    assert.equal(report.status, 'passed');
    assert.equal(report.scope, 'partial');
    assert.equal(report.cleanup.completed, true);
    assert.equal(report.results[0].tests, 1);
    assert.equal(report.results[0].skipped, 0);
    assert.equal(report.results[0].target, 'identity-api:./internal/mfa');
    assert.deepEqual(report.results[0].packageEvidence, [{ package: `${identityGoModule}/internal/mfa`, tests: ['TestOwnedFixture'] }]);
    assert.equal(state.maximumActive, 1);
    assert.equal(state.active, 0);
    assert.deepEqual(docker.removed, ['nats', 'redis', 'postgres', 'network']);
    assert.equal(docker.ownershipViolation, false);
    assert.deepEqual(JSON.parse(readFileSync(join(directory, 'race---internal-mfa.json'))), report);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|private\/path/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('unsupported real toolchain capabilities fail before service allocation regardless of caller claims', async (t) => {
  const cases = [
    ['Windows Go', { go: { ...fixtureToolchain.go, GOOS: 'windows', GOHOSTOS: 'windows' } }],
    ['cross host', { go: { ...fixtureToolchain.go, GOHOSTOS: 'windows' } }],
    ['cross target', { go: { ...fixtureToolchain.go, GOOS: 'windows' } }],
    ['wrong architecture', { go: { ...fixtureToolchain.go, GOARCH: 'arm64' } }],
    ['cgo zero', { go: { ...fixtureToolchain.go, CGO_ENABLED: '0' } }],
    ['cgo boolean', { go: { ...fixtureToolchain.go, CGO_ENABLED: true } }],
    ['old Go', { go: { ...fixtureToolchain.go, GOVERSION: 'go1.26.4' } }],
    ['development Go', { go: { ...fixtureToolchain.go, GOVERSION: 'devel go1.27 PRIVATE' } }],
    ['malformed JSON', { goOutput: 'PRIVATE not-json' }],
    ['missing env field', { goOutput: '{"GOOS":"linux"}' }],
    ['duplicate env field', { goOutput: JSON.stringify(fixtureToolchain.go).replace('"GOOS":', '"GOOS":"windows","GOOS":') }],
    ['unknown private field', { go: { ...fixtureToolchain.go, GOROOT: 'PRIVATE path' } }],
    ['clang banner', { version: 'Ubuntu clang version 17.0.0\nPRIVATE' }],
    ['malformed GCC version', { version: 'PRIVATE compiler' }],
    ['Windows GCC', { target: 'x86_64-w64-mingw32\n' }],
    ['wrong GCC architecture', { target: 'aarch64-linux-gnu\n' }],
    ['wrong GCC ABI', { target: 'x86_64-linux-gnux32\n' }],
    ['extra GCC target output', { target: 'x86_64-linux-gnu\nPRIVATE' }],
    ['missing command', { result: { error: new Error('PRIVATE spawn error'), status: null } }],
    ['nonzero command', { result: { status: 1, stderr: 'PRIVATE diagnostic' } }],
    ['interrupted command', { result: { signal: 'SIGTERM' } }],
    ['overflowing command', { goOutput: 'PRIVATE'.repeat(5000) }],
    ['unexpected command diagnostic', { result: { stderr: 'PRIVATE diagnostic' } }],
  ];
  for (const [name, options] of cases) await t.test(name, async (t) => {
    const calls = mockToolchainProbes(t, options);
    let allocated = 0;
    await assert.rejects(runPortalIntegrationSuites({ identify,
      invocation: integrationInvocation(['--integration-race-package=./internal/mfa']),
      toolchain: fixtureToolchain, linuxVerified: true,
      startServices: async () => { allocated++; throw new Error('Unexpected service allocation'); },
    }), (error) => {
      assert.doesNotMatch(error.message, /PRIVATE|\/private\/|Unexpected service/);
      return true;
    });
    assert(calls.length > 0 && calls.length <= 3);
    assert.equal(allocated, 0);
  });
});

test('toolchain commands exclude caller OS/compiler overrides and capability toggles', async (t) => {
  const values = { GOOS: 'linux', GOHOSTOS: 'linux', GOARCH: 'amd64', GOVERSION: 'go9.99.99', CGO_ENABLED: '0',
    GO: 'PRIVATE arbitrary executable', GCC: 'PRIVATE arbitrary executable', CC: 'PRIVATE --wrapper', RACE_TOOLCHAIN_VERIFIED: '1' };
  const previous = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const calls = mockToolchainProbes(t, { go: { ...fixtureToolchain.go, GOHOSTOS: 'windows' } });
  let allocated = 0;
  await assert.rejects(runPortalIntegrationSuites({ identify, invocation: integrationInvocation(['--integration-race-package=./internal/mfa']),
    toolchain: fixtureToolchain, startServices: async () => { allocated++; },
  }), /actual Linux host/);
  assert.equal(calls.length, 3);
  assert.equal(allocated, 0);
});

test('toolchain startup budget is one lifecycle deadline, including compiler probes and interruption', async (t) => {
  for (const mode of ['deadline', 'signal']) await t.test(mode, async (t) => {
    let now = Date.now(), allocated = 0;
    t.mock.method(Date, 'now', () => now);
    const lifecycle = acceptanceLifecycle({ timeout: 60_000, reserve: 10_000 });
    const calls = mockToolchainProbes(t, { afterProbe(index) {
      if (mode === 'deadline') now += index === 1 ? 45_000 : 10_000;
      else process.emit('SIGTERM');
    } });
    await assert.rejects(runPortalIntegrationSuites({ identify, lifecycle, invocation: integrationInvocation(['--integration-race-package=./internal/mfa']),
      startServices: async () => { allocated++; },
    }));
    assert.equal(allocated, 0);
    if (mode === 'deadline') { assert.equal(calls.length, 2); assert.equal(calls[1].options.timeout, 5000); }
    else assert.equal(calls.length, 1);
  });
});

test('integration runner executes all seven uncached mandatory suites serially and confirms owned service cleanup', async (t) => {
  const docker = mockPortalDocker(t);
  const state = mockIntegrationRunner(t);
  await runPortalIntegrationSuites({ identify });
  assert.deepEqual(state.children.map((child) => child.target), integrationTargets.map((target) => `identity-api:${target}`));
  assert.equal(state.maximumActive, 1);
  assert.equal(state.active, 0);
  assert.equal(state.terminated.length, 0);
  assert.deepEqual(docker.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(docker.ownershipViolation, false);
  assert(state.messages.some((message) => message.includes('serial-integration-teardown')));
  assert.doesNotMatch(state.messages.join(''), /PRIVATE/);
});

test('integration runner fails closed on a prerequisite failure without running later suites or leaking diagnostics', async (t) => {
  const docker = mockPortalDocker(t);
  const state = mockIntegrationRunner(t, { failAt: 2, output(child) {
    if (child.target === `identity-api:${integrationTargets[1]}`)
      child.stderr.emit('data', 'build cache is required, but could not be located: GOCACHE is not defined\nPRIVATE body\n');
    else for (const name of integrationPackages[child.target.slice('identity-api:'.length)]) child.stdout.emit('data', `--- PASS: TestOwnedFixture\nok ${identityGoModule}/${name}\t0.01s\n`);
  } });
  await assert.rejects(runPortalIntegrationSuites({ identify }), /Required test-admin-integration failed/);
  assert.equal(state.children.length, 2);
  assert.deepEqual(docker.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.deepEqual(failureCategories('build cache is required, GOCACHE is not defined'), ['go-build-cache']);
  assert.doesNotMatch(state.messages.join(''), /PRIVATE|GOCACHE|build cache is required/);
});

test('integration runner bounds private summaries and rejects skips, test failures, missing evidence and process errors', async (t) => {
  for (const kind of ['skipped', 'failed', 'no-evidence', 'exit', 'start']) {
    await t.test(kind, async (t) => {
      const state = mockIntegrationRunner(t, { startError: kind === 'start', exit: kind === 'exit' ? 130 : 0,
        output(child) {
          child.stderr.emit('data', 'PRIVATE'.repeat(20_000));
          child.stderr.emit('data', '\n');
          if (kind === 'no-evidence') return;
          child.stdout.emit('data', '--- PASS: TestOwnedFixture\nok fixture/package\n');
          if (kind === 'skipped') child.stdout.emit('data', '--- SKIP: TestOwnedSkip\n');
          if (kind === 'failed') for (let index = 0; index < 40; index++) {
            child.stdout.emit('data', `--- FAIL: TestOwned${index}\n source${index}.go:12: PRIVATE assertion\n`);
          }
        },
      });
      await assert.rejects(runPortalIntegrationTarget(integrationTargets[0], {}), (error) => !error.message.includes('PRIVATE'));
      assert.equal(state.active, 0);
      assert.doesNotMatch(state.messages.join(''), /PRIVATE|assertion|process error/);
      for (const message of state.messages) {
        const summary = JSON.parse(message);
        assert((summary.failures?.length ?? 0) <= 30);
        assert((summary.locations?.length ?? 0) <= 30);
        assert((summary.categories?.length ?? 0) <= 12);
      }
    });
  }
});

test('integration runner deadline and interruption terminate only the owned process tree before returning', async (t) => {
  for (const kind of ['deadline', 'interrupted']) await t.test(kind, async (t) => {
    const state = mockIntegrationRunner(t, { hang: true });
    const pending = runPortalIntegrationTarget(integrationTargets[0], {}, kind === 'deadline' ? 10 : 1000);
    state.children[0].stdout.emit('data', '--- FAIL: TestOwnedDeadline\n source.go:12: PRIVATE assertion\n');
    state.children[0].stderr.emit('data', 'build cache is required: GOCACHE is not defined');
    if (kind === 'interrupted') process.emit('SIGTERM');
    await assert.rejects(pending, new RegExp(kind));
    assert.equal(state.active, 0);
    assert.deepEqual(state.terminated, [process.platform === 'win32' ? 'owned-tree' : 'SIGTERM']);
    assert.doesNotMatch(state.messages.join(''), /100000|PRIVATE/);
    const summary = JSON.parse(state.messages.at(-1));
    assert.deepEqual(summary.failures, ['TestOwnedDeadline']);
    assert.deepEqual(summary.locations, ['source.go:12']);
    assert.deepEqual(summary.categories, ['go-build-cache']);
  });
});

test('integration runner total deadline includes startup and never resets between mandatory suites', async (t) => {
  const docker = mockPortalDocker(t);
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const state = mockIntegrationRunner(t, { output(child) {
    for (const name of integrationPackages[child.target.slice('identity-api:'.length)]) child.stdout.emit('data', `--- PASS: TestOwnedFixture\nok ${identityGoModule}/${name}\t0.01s\n`);
    now += 58 * 60_000;
  } });
  await assert.rejects(runPortalIntegrationSuites({ identify }), /Integration runner deadline exceeded/);
  assert.equal(state.children.length, 1);
  assert.equal(state.active, 0);
  assert.deepEqual(docker.removed, ['nats', 'redis', 'postgres', 'network']);
});

test('POSIX integration interruption signals the owned detached process group', async (t) => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  t.after(() => Object.defineProperty(process, 'platform', platform));
  const state = mockIntegrationRunner(t, { hang: true });
  await assert.rejects(runPortalIntegrationTarget(integrationTargets[0], {}, 10), /deadline/);
  assert.equal(state.children[0].options.detached, true);
  assert.deepEqual(state.terminated, ['SIGTERM']);
  assert.equal(state.active, 0);
});

test('integration runner refuses an unknown suite or an absent, infinite or excessive deadline before spawning', async (t) => {
  const state = mockIntegrationRunner(t);
  await assert.rejects(runPortalIntegrationTarget('test-unknown', {}), /Unknown required/);
  for (const timeout of [0, -1, NaN, Infinity, 30 * 60_000 + 1])
    await assert.rejects(runPortalIntegrationTarget(integrationTargets[0], {}, timeout), /Invalid integration deadline/);
  assert.equal(state.children.length, 0);
});

test('integration runner deadline tears down a real owned Node process and its descendant', async (t) => {
 for (const output of ['inherit', 'ignore']) await t.test(output, async (t) => {
  const originalSpawn = childProcess.spawn;
  const messages = [];
  let root, descendant;
  t.mock.method(console, 'log', (message) => messages.push(message));
  t.mock.method(childProcess, 'spawn', (_command, _args, options) => {
    root = originalSpawn(process.execPath, ['-e', `
      const { spawn } = require('node:child_process');
      const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
        stdio: ['ignore', '${output}', '${output}'],
      });
      console.log('OWNED_DESCENDANT=' + child.pid);
      process.on('SIGTERM', () => {
        if (child.exitCode !== null || child.signalCode !== null) process.exit(0);
        child.once('exit', () => process.exit(0));
      });
      setInterval(() => {}, 1000);
    `], options);
    root.stdout.on('data', (chunk) => {
      const match = String(chunk).match(/OWNED_DESCENDANT=(\d+)/);
      if (match) descendant = Number(match[1]);
    });
    return root;
  });
  syncBuiltinESMExports();
  const alive = (pid) => {
    try { process.kill(pid, 0); return true; } catch (error) {
      assert.equal(error.code, 'ESRCH');
      return false;
    }
  };
  t.after(() => {
    for (const pid of [root?.pid, descendant]) if (pid && alive(pid)) {
      if (process.platform === 'win32') childProcess.spawnSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
        stdio: 'ignore', timeout: 10_000, windowsHide: true,
      });
      else process.kill(pid, 'SIGKILL');
    }
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  await assert.rejects(runPortalIntegrationTarget(integrationTargets[0], {}, 2000), /deadline/);
  assert(Number.isSafeInteger(descendant), 'The real owned descendant was not started');
  assert.equal(alive(root.pid), false, 'The owned runner process survived teardown');
  assert.equal(alive(descendant), false, 'An owned descendant survived teardown');
  assert.doesNotMatch(messages.join(''), /OWNED_DESCENDANT/);
 });
});

test('portal cleanup preserves fresh service ownership and successful idempotent close with mocked Docker', async (t) => {
  const state = mockPortalDocker(t);
  const ids = new Set();
  for (let run = 0; run < 2; run++) {
    const services = await startPortalServices();
    assert.match(services.runID, /^[a-f0-9]{32}$/);
    ids.add(services.runID);
    assert(state.created.slice(run * 3).every(({ id, operation }) => operation === 'create' && id.startsWith(`portal-browser-${services.runID}-`)));
    const pending = services.close();
    assert.equal(services.close(), pending);
    assert.deepEqual(await pending, { completed: true });
    assert.equal(services.close(), pending);
  }
  assert.equal(ids.size, 2);
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network', 'nats', 'redis', 'postgres', 'network']);
  assert.equal(state.ownershipViolation, false);
});

test('portal restartable broker keeps client and monitoring loopback bindings across Docker restart', async (t) => {
  const state = mockPortalDocker(t);
  const services = await startPortalServices({ integration: true });
  try {
    const id = services.environment.LIFECYCLE_TEST_NATS_CONTAINER;
    const inspect = () => JSON.parse(childProcess.spawnSync('docker', ['inspect', id]).stdout)[0].NetworkSettings.Ports;
    const before = inspect();
    assert.equal(new URL(services.environment.NATS_URL).port, before['4222/tcp'][0].HostPort);
    childProcess.spawnSync('docker', ['restart', id]);
    assert.deepEqual(inspect(), before, 'Restart reassigned an endpoint retained by the lifecycle client');
    const broker = state.created.find((container) => container.id === id);
    assert.equal(broker.operation, 'create', 'Restartable broker ownership must precede its port-binding start');
    assert.deepEqual(state.started, state.created.map(({ id }) => id));
    assert(Object.values(broker.ports).every((binding) => binding.requested && String(binding.actual) === binding.requested));
    assert.equal(state.reservedPorts, 2);
    assert.equal(state.releasedPorts, 2);
  } finally { await services.close(); }
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(state.ownershipViolation, false);
});

test('portal cleanup removes its created broker after a port-binding start failure', async (t) => {
  const state = mockPortalDocker(t, { failStart: 'nats' });
  await assert.rejects(startPortalServices({ integration: true }), /Disposable Docker start failed/);
  assert.deepEqual(state.created.map(({ kind }) => kind), ['postgres', 'redis', 'nats']);
  assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  assert.equal(state.releasedPorts, state.reservedPorts);
  assert.equal(state.ownershipViolation, false);
});

test('ordinary service start failures remove the Created container and only earlier run-owned resources', async (t) => {
  const order = ['postgres', 'redis', 'nats'];
  for (const [index, kind] of order.entries()) {
    await t.test(kind, async (t) => {
      const state = mockPortalDocker(t, { failStart: kind });
      await assert.rejects(startPortalServices(), /Disposable Docker start failed/);
      assert.deepEqual(state.created.map(({ kind }) => kind), order.slice(0, index + 1));
      assert(state.created.every(({ operation }) => operation === 'create'));
      assert.deepEqual(state.started.map((id) => id.split('-').at(-1)), order.slice(0, index));
      assert.deepEqual(state.removed, [...order.slice(0, index + 1).reverse(), 'network']);
      assert.equal(state.ownershipViolation, false, 'Start-failure cleanup adopted an unowned resource');
      assert.equal(state.reservedPorts, 0, 'Ordinary service changes altered special broker port reservation');
    });
  }
});

test('portal cleanup rejects nonzero mocked Docker removal after trying every owned resource', async (t) => {
  for (const kind of ['nats', 'redis', 'postgres', 'network']) {
    await t.test(kind, async (t) => {
      const state = mockPortalDocker(t, { failCleanup: kind });
      const services = await startPortalServices();
      const pending = services.close();
      assert.equal(services.close(), pending);
      await assert.rejects(pending, /Disposable portal cleanup did not complete/);
      const remaining = [];
      const harnessClose = portalCleanup([() => remaining.push('after'), services.close, () => remaining.push('before')]);
      await assert.rejects(harnessClose(), /Disposable portal cleanup did not complete/);
      await assert.rejects(services.close(), /Disposable portal cleanup did not complete/);
      assert.deepEqual(remaining, ['before', 'after']);
      assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
      assert.equal(state.ownershipViolation, false);
    });
  }
});

test('portal cleanup unwinds failed mocked startup without removing an unowned broker', async (t) => {
  for (const cleanupFails of [false, true]) {
    await t.test(cleanupFails ? 'startup and cleanup failure' : 'startup failure', async (t) => {
      const state = mockPortalDocker(t, { failCreate: 'nats', failCleanup: cleanupFails ? 'redis' : undefined });
      await assert.rejects(startPortalServices({ integration: true }), cleanupFails
        ? /Disposable portal cleanup did not complete/
        : /Disposable Docker create failed/);
      assert.equal(state.rejectedName, 'admin-test-nats');
      assert.deepEqual(state.created.map(({ kind }) => kind), ['postgres', 'redis']);
      assert.deepEqual(state.removed, ['redis', 'postgres', 'network']);
      assert.equal(state.ownershipViolation, false);
    });
  }
});

function statusObservation() {
  const cdp = new EventEmitter();
  const observer = observeStatusPatches(cdp, 'https://localhost:43210');
  let sequence = 0;
  return {
    cdp, observer,
    request({ nonce, postData = '{"status":"banned","reason":"PRIVATE-REASON","expected_revision":"1"}' } = {}) {
      const requestId = `request-${++sequence}`;
      cdp.emit('Network.requestWillBeSent', { requestId, request: {
        url: 'https://localhost:43210/api/v1/admin/users/PRIVATE-SUBJECT/status', method: 'PATCH', postData,
        headers: { DPoP: `header.${Buffer.from(JSON.stringify({ nonce })).toString('base64url')}.signature`,
          'X-Step-Up-Auth': 'PRIVATE-GRANT', 'X-Portal-Session': 'PRIVATE-SESSION' },
      } });
      return requestId;
    },
    response(networkId, status, {
      headers = status === 401 ? [
        { name: 'DPoP-Nonce', value: 'PRIVATE-NONCE' },
        { name: 'WWW-Authenticate', value: 'DPoP error="use_dpop_nonce"' },
      ] : [],
      body = '{"error":"use_dpop_nonce"}',
    } = {}) {
      observer.response({ networkId, responseStatusCode: status, responseHeaders: headers }, body);
    },
  };
}

test('admin status PATCH observation accepts only the initial exact nonce retry of the same mutation', () => {
  for (const challenged of [false, true]) {
    const wire = statusObservation();
    try {
      const first = wire.request();
      wire.response(first, challenged ? 401 : 204);
      if (challenged) wire.response(wire.request({ nonce: 'PRIVATE-NONCE' }), 204);
      const expected = { outgoingStatusPatches: challenged ? 2 : 1, preHandlerNonceRetries: challenged ? 1 : 0, reconciliationStatusPatches: 0 };
      assert.deepEqual(wire.observer.assertLostResponse(), expected);
      wire.observer.reconcile();
      assert.deepEqual(wire.observer.assertLostResponse(), expected);
      assert.doesNotMatch(JSON.stringify(expected), /PRIVATE-|DPoP|reason|headers|body/);
    } finally { wire.observer.close(); }
    assert.equal(wire.cdp.listenerCount('Network.requestWillBeSent'), 0);
  }
  for (const challenge of [
    { status: 403 },
    { headers: [] },
    { body: '{"error":"invalid_credentials"}' },
    { body: '{"error":' },
    { headers: [{ name: 'DPoP-Nonce', value: 'PRIVATE-NONCE' }, { name: 'WWW-Authenticate', value: 'Basic realm="DPoP error=use_dpop_nonce"' }] },
    { headers: [{ name: 'DPoP-Nonce', value: 'PRIVATE-NONCE' }, { name: 'DPoP-Nonce', value: 'duplicate' }, { name: 'WWW-Authenticate', value: 'DPoP error="use_dpop_nonce"' }] },
    { retry: { nonce: 'wrong-nonce' } },
    { retry: { nonce: 'PRIVATE-NONCE', postData: '{"reason":"CHANGED-PRIVATE-REASON"}' } },
  ]) {
    const wire = statusObservation();
    try {
      assert.throws(() => {
        wire.response(wire.request(), challenge.status || 401, challenge);
        wire.response(wire.request(challenge.retry || { nonce: 'PRIVATE-NONCE' }), 204);
        wire.observer.assertLostResponse();
      });
    } finally { wire.observer.close(); }
  }
});

test('admin status PATCH observation rejects every failed replay through current-state reconciliation', () => {
  for (const challenged of [false, true]) {
    for (const reconciling of [false, true]) {
      for (const status of [undefined, 401, 403, 409, 429, 503]) {
        const wire = statusObservation();
        try {
          wire.response(wire.request(), challenged ? 401 : 204);
          if (challenged) wire.response(wire.request({ nonce: 'PRIVATE-NONCE' }), 204);
          wire.observer.assertLostResponse();
          if (reconciling) wire.observer.reconcile();
          const replay = wire.request();
          if (status !== undefined) wire.response(replay, status);
          assert.equal(wire.observer.count, challenged ? 3 : 2);
          assert.throws(() => wire.observer.assertLostResponse());
        } finally { wire.observer.close(); }
      }
    }
  }
  const early = statusObservation();
  try {
    const initial = early.request();
    const prematureRetry = early.request({ nonce: 'PRIVATE-NONCE' });
    early.response(initial, 401);
    early.response(prematureRetry, 204);
    assert.throws(() => early.observer.assertLostResponse(), 'A retry before the challenge was accepted');
  } finally { early.observer.close(); }
});

test('admin privacy markers register console/URL secrets and reject drafts, payloads and reason telemetry', () => {
  const context = new EventEmitter();
  const harness = { origin: 'https://localhost:43210', secrets: [] };
  const markers = { reason: 'PRIVATE-REASON', cancelledDraft: 'PRIVATE-DRAFT', auditPayload: 'PRIVATE-PAYLOAD' };
  const failures = [];
  observeAdminMarkers(context, harness, markers, failures);
  assert.deepEqual(harness.secrets, Object.values(markers));
  const request = (body, path = '/api/v1/admin/users/subject/status', headers = {}) => context.emit('request', {
    method: () => 'PATCH', url: () => harness.origin + path, headers: () => headers,
    postData: () => JSON.stringify(body),
  });
  request({ status: 'banned', reason: markers.reason, expected_revision: '1' });
  assert.deepEqual(failures, []);
  request({ reason: markers.cancelledDraft });
  request({ payload: markers.auditPayload }, '/telemetry');
  request({ reason: markers.reason }, '/telemetry');
  request({ reason: markers.reason, unexpected: markers.reason });
  request({}, `/api/v1/admin/audit-logs?payload=${markers.auditPayload}`);
  request({}, '/api/v1/admin/capabilities', { Referer: markers.cancelledDraft });
  assert.equal(failures.length, 6);
  assert.doesNotMatch(JSON.stringify(failures), /PRIVATE-|subject|telemetry/);
});

function legalWriteObservation(method = 'POST') {
  const cdp = new EventEmitter();
  const origin = 'https://localhost:43210';
  const observer = observeLegalWrites(cdp, origin);
  let sequence = 0;
  return {
    cdp, observer,
    request({ nonce, path = method === 'POST' ? '/api/v1/admin/legal-holds' : `/api/v1/admin/legal-holds/${legalHoldID}`,
      postData = method === 'POST' ? JSON.stringify({ account_ref: legalAccount, reason: 'PRIVATE-REASON' }) : undefined,
      key = method === 'POST' ? legalOperationID : undefined, grant = 'PRIVATE-GRANT', session = 'PRIVATE-SESSION' } = {}) {
      const requestId = `legal-request-${++sequence}`;
      cdp.emit('Network.requestWillBeSent', { requestId, request: {
        method, url: origin + path, postData, headers: {
          DPoP: `header.${Buffer.from(JSON.stringify({ nonce })).toString('base64url')}.signature`,
          'X-Step-Up-Auth': grant, 'X-Portal-Session': session, ...(key ? { 'Idempotency-Key': key } : {}),
        },
      } });
      return requestId;
    },
    response(networkId, status, { body = '{"error":"use_dpop_nonce"}', headers = status === 401 ? [
      { name: 'DPoP-Nonce', value: 'PRIVATE-NONCE' }, { name: 'WWW-Authenticate', value: 'DPoP error="use_dpop_nonce"' },
    ] : [] } = {}) {
      observer.response({ networkId, responseStatusCode: status, responseHeaders: headers }, body);
    },
  };
}

test('lost legal write observation accepts only one success and its exact pre-handler nonce retry', () => {
  for (const method of ['POST', 'DELETE']) {
    for (const nonce of [false, true]) {
      const wire = legalWriteObservation(method);
      const status = method === 'POST' ? 201 : 204;
      try {
        wire.response(wire.request(), nonce ? 401 : status);
        if (nonce) wire.response(wire.request({ nonce: 'PRIVATE-NONCE' }), status);
        wire.observer.reconcile();
        const report = wire.observer.assertLostResponse(status);
        assert.deepEqual(report, { outgoingLegalWrites: nonce ? 2 : 1, preHandlerNonceRetries: nonce ? 1 : 0, reconciliationWrites: 0 });
        assert.doesNotMatch(JSON.stringify(report), /PRIVATE|account_ref|body|Idempotency/);
      } finally { wire.observer.close(); }
      assert.equal(wire.cdp.listenerCount('Network.requestWillBeSent'), 0);
    }
  }
  for (const retry of [
    { nonce: 'PRIVATE-NONCE', key: legalHoldID },
    { nonce: 'PRIVATE-NONCE', postData: '{"reason":"PRIVATE-CHANGED"}' },
    { nonce: 'PRIVATE-NONCE', path: '/api/v1/admin/preservation-requests' },
    { nonce: 'PRIVATE-NONCE', grant: 'PRIVATE-OTHER-GRANT' },
    { nonce: 'PRIVATE-NONCE', session: 'PRIVATE-OTHER-SESSION' },
    { nonce: 'PRIVATE-WRONG-NONCE' },
  ]) {
    const wire = legalWriteObservation();
    try {
      wire.response(wire.request(), 401);
      wire.response(wire.request(retry), 201);
      assert.throws(() => wire.observer.assertLostResponse(201));
    } finally { wire.observer.close(); }
  }
  for (const challenge of [{ body: '{"error":"invalid_credentials"}' }, { headers: [] }, { body: '{"error":' }]) {
    const wire = legalWriteObservation();
    try {
      assert.throws(() => {
        wire.response(wire.request(), 401, challenge);
        wire.response(wire.request({ nonce: 'PRIVATE-NONCE' }), 201);
        wire.observer.assertLostResponse(201);
      });
    } finally { wire.observer.close(); }
  }
});

test('every automatic legal replay fails observation, including denied attempts during state reconciliation', () => {
  for (const method of ['POST', 'DELETE']) for (const lateStatus of [undefined, 401, 403, 409, 429, 503]) {
    const wire = legalWriteObservation(method);
    const success = method === 'POST' ? 201 : 204;
    try {
      wire.response(wire.request(), success);
      wire.observer.reconcile();
      const late = wire.request();
      if (lateStatus !== undefined) wire.response(late, lateStatus);
      assert.throws(() => wire.observer.assertLostResponse(success));
    } finally { wire.observer.close(); }
  }
  const early = legalWriteObservation();
  try {
    const first = early.request();
    const premature = early.request({ nonce: 'PRIVATE-NONCE' });
    early.response(first, 401);
    early.response(premature, 201);
    assert.throws(() => early.observer.assertLostResponse(201));
  } finally { early.observer.close(); }
  const badRelease = legalWriteObservation('DELETE');
  try {
    badRelease.request({ key: legalOperationID, postData: '{"reason":"PRIVATE"}' });
    assert.throws(() => badRelease.observer.count);
  } finally { badRelease.observer.close(); }
});

test('legal privacy observations reject result, narrative, operation, grant and cursor copies outside exact boundaries', () => {
  const context = new EventEmitter();
  const markers = { reason: 'PRIVATE-LEGAL-REASON', requesting_authority: 'PRIVATE-AUTHORITY',
    identifier: 'private@example.test', cancelledDraft: 'PRIVATE-UNSENT-DRAFT' };
  const harness = { origin: 'https://localhost:43210', secrets: [], legalSecrets: new Set([legalAccount, legalHoldID, 'PRIVATE-CURSOR', 'PRIVATE-RESULT']),
    legalReferences: { accounts: new Set([legalAccount]), holds: new Set([legalHoldID]) }, routeReferences: new Set() };
  const failures = [];
  observeLegalPrivacy(context, harness, markers, failures);
  const request = (path, method = 'POST', body = {}, headers = {}, navigation = false) => context.emit('request', {
    url: () => harness.origin + path, method: () => method, postData: () => method === 'POST' ? JSON.stringify(body) : null,
    headers: () => headers, isNavigationRequest: () => navigation,
  });
  request('/api/v1/admin/legal-holds', 'POST', { account_ref: legalAccount, reason: markers.reason,
    requesting_authority: markers.requesting_authority }, { 'Idempotency-Key': legalOperationID, DPoP: 'PRIVATE-DPOP', 'X-Step-Up-Auth': 'PRIVATE-GRANT' });
  request(`/api/v1/admin/legal-holds?account_ref=${legalAccount}`, 'GET');
  request(`/api/v1/admin/legal-holds/${legalHoldID}`, 'DELETE');
  request('/api/v1/admin/legal-inquiry/lookup', 'POST', { identifier: markers.identifier, cursor: 'PRIVATE-CURSOR' });
  assert.deepEqual(failures, []);
  assert(harness.secrets.includes(legalOperationID) && harness.secrets.includes('PRIVATE-DPOP') && harness.secrets.includes('PRIVATE-GRANT'));
  request('/telemetry', 'POST', { reason: markers.reason });
  request('/api/v1/admin/legal-holds', 'POST', { reason: markers.cancelledDraft });
  request('/api/v1/admin/legal-holds', 'POST', { reason: markers.reason, unexpected: 'PRIVATE-RESULT' });
  request(`/admin/legal?account_ref=${legalAccount}`, 'GET');
  request(`/api/v1/admin/legal-holds?account_ref=${legalAccount}`, 'GET', {}, {}, true);
  request(`/api/v1/admin/legal-holds?cursor=PRIVATE-CURSOR`, 'GET');
  request('/api/v1/admin/legal-holds', 'GET', {}, { 'X-Debug': markers.reason });
  request('/api/v1/admin/legal-inquiry/lookup', 'POST', {}, { 'Idempotency-Key': legalOperationID });
  request('/api/v1/admin/legal-holds', 'POST', {}, { 'X-Debug': 'PRIVATE-GRANT' });
  request('/api/v1/users/me', 'GET', {}, { 'X-Step-Up-Auth': 'PRIVATE-GRANT' });
  request('/telemetry', 'POST', { proof: 'PRIVATE-DPOP' });
  request('/telemetry', 'POST', { key: legalOperationID });
  assert.equal(failures.length, 12);
  assert.doesNotMatch(JSON.stringify(failures), /PRIVATE-|private@example|account_ref|CURSOR/);
});

test('base and legal observers agree on known coordinates without exempting arbitrary URLs or disclosures', async () => {
  const coordinate = '9007199254740993';
  const origin = 'https://localhost:43210';
  const observeRequest = async ({ path, method = 'GET', headers = {}, body, navigation = false }) => {
    const context = Object.assign(new EventEmitter(), {
      setDefaultTimeout() {}, setDefaultNavigationTimeout() {}, async addInitScript() {},
    });
    const harness = { origin, secrets: [coordinate], legalSecrets: new Set([coordinate]), routeReferences: new Set(),
      legalReferences: { accounts: new Set(), holds: new Set() } };
    const { observed } = await newContext({ newContext: async () => context }, harness);
    const legal = [];
    observeLegalPrivacy(context, harness, {}, legal);
    const page = new EventEmitter();
    context.emit('page', page);
    const request = { url: () => path.startsWith('/') ? origin + path : path, method: () => method,
      headers: () => headers, postData: () => body === undefined ? null : JSON.stringify(body),
      isNavigationRequest: () => navigation };
    page.emit('request', request);
    context.emit('request', request);
    return { base: observed.failures, legal, allowed: legalCoordinateRequest(request, coordinate, harness) };
  };
  for (const path of [
    `/api/v1/admin/audit-logs?before_seq=${coordinate}&limit=2`,
    `/api/v1/admin/audit-logs/verify?after_seq=${coordinate}&limit=5`,
    `/api/v1/admin/audit-logs/verify?through_seq=${coordinate}&after_seq=0`,
    `/api/v1/admin/ledger/verify?after_seq=${coordinate}&limit=5`,
    `/api/v1/admin/ledger/verify?through_seq=${coordinate}&after_seq=0`,
  ]) assert.deepEqual(await observeRequest({ path }), { base: [], legal: [], allowed: true });
  for (const request of [
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}`, navigation: true },
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}`, method: 'POST' },
    { path: `/admin/legal?after_seq=${coordinate}` },
    { path: `/api/v1/admin/users?after_seq=${coordinate}` },
    { path: `/api/v1/admin/audit-logs?after_seq=${coordinate}` },
    { path: `/api/v1/admin/ledger/verify?before_seq=${coordinate}` },
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}&after_seq=${coordinate}` },
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}&debug=${coordinate}` },
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}&limit=1&limit=2` },
    { path: `/api/v1/admin/ledger/verify?after_seq=0${coordinate}` },
    { path: `/api/v1/admin/ledger/verify?after_seq=${coordinate}#${coordinate}` },
    { path: `https://other.example.test/api/v1/admin/ledger/verify?after_seq=${coordinate}` },
    { path: `https://${coordinate}@localhost:43210/api/v1/admin/ledger/verify?after_seq=${coordinate}` },
  ]) {
    const result = await observeRequest(request);
    assert.equal(result.allowed, false);
    assert(result.base.length > 0 && result.legal.length > 0);
  }
  for (const request of [
    { path: '/api/v1/users/me', headers: { 'X-Debug': coordinate } },
    { path: '/telemetry', method: 'POST', body: { result: coordinate } },
    { path: '/api/v1/admin/legal-inquiry/lookup', method: 'POST', body: { result: coordinate } },
  ]) {
    const result = await observeRequest(request);
    assert.equal(result.allowed, false);
    assert(result.legal.length > 0);
  }
});

test('coordinate exceptions require a known canonical signed-64 value', () => {
  const origin = 'https://localhost:43210';
  for (const value of ['01', '-1', '1.0', '9223372036854775808', '9007199254740993']) {
    const request = { url: () => `${origin}/api/v1/admin/ledger/verify?after_seq=${value}`,
      method: () => 'GET', isNavigationRequest: () => false };
    const legalSecrets = new Set(value === '9007199254740993' ? [] : [value]);
    assert.equal(legalCoordinateRequest(request, value, { origin, legalSecrets }), false);
  }
});

test('privacy observer diagnostics are fixed category counts, never raw failures or route suffixes', async () => {
  const messages = [];
  const previous = console.error;
  console.error = (message) => messages.push(message);
  try {
    await assert.rejects(clean(undefined, { pending: [], failures: [
      'Fixture secret appeared in a request URL', 'Fixture secret appeared in a request URL',
      'Invalid or reused outgoing browser proof for PRIVATE-ROUTE',
      'API privacy/auth response policy failed for PRIVATE-ROUTE', 'private@example.test',
    ] }));
  } finally { console.error = previous; }
  assert.deepEqual(messages.map((message) => JSON.parse(message)), [{ check: 'portal-observers',
    counts: { 'url-data': 2, proof: 1, 'response-policy': 1, other: 1 } }]);
  assert.doesNotMatch(messages.join(''), /PRIVATE|private@example|request URL/);
});

const adminScript = fileURLToPath(new URL('./web-admin.browser.mjs', import.meta.url));
const adminCommand = 'npm exec -- nx run web:test-admin-browser --skipNxCache';
function adminEvidenceOptions(directory) {
  return {
    directory,
    start: async () => ({ runID: 'a'.repeat(32), secrets: ['PRIVATE-FAILURE'], diagnostics() {}, close: async () => ({ completed: true }) }),
    validate: async () => ({ checks: ['controlled assertion'], layouts: 0, manualGates: ['Native/manual checks remain'] }),
    identity: async () => ({ root: '/fixture/worktree', head: '1'.repeat(40), dirty: true, stagedDiffSHA256: '2'.repeat(64) }),
    invocation: () => adminInvocation({ argv: [process.execPath, adminScript], execArgv: [], declared: adminCommand }),
    guard: () => () => {},
  };
}

test('admin invocation evidence records exact executable arguments and rejects arbitrary credential-bearing commands', () => {
  const invocation = adminEvidenceOptions().invocation();
  assert.equal(invocation.executable, process.execPath);
  assert.deepEqual(invocation.arguments, [adminScript]);
  assert.equal(invocation.declaredOuterCommand, adminCommand);
  for (const options of [
    { argv: [process.execPath, adminScript, 'PRIVATE-CREDENTIAL'] },
    { argv: [process.execPath, adminScript], execArgv: ['--eval', 'PRIVATE-CREDENTIAL'] },
    { argv: [process.execPath, adminScript], declared: `${adminCommand} PRIVATE-CREDENTIAL` },
  ]) assert.throws(() => adminInvocation({ execArgv: [], ...options }));
});

test('admin worktree identity exposes only its root, revision and opaque source digests', async () => {
  const identity = await adminWorktreeIdentity();
  assert.deepEqual(Object.keys(identity).sort(), ['dirty', 'head', 'root', 'stagedDiffSHA256', 'statusSHA256', 'unstagedDiffSHA256', 'untrackedSHA256']);
  assert.equal(typeof identity.root, 'string');
  assert.equal(typeof identity.dirty, 'boolean');
  assert.match(identity.head, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
  for (const field of ['stagedDiffSHA256', 'statusSHA256', 'unstagedDiffSHA256', 'untrackedSHA256'])
    assert.match(identity[field], /^[a-f0-9]{64}$/);
});

test('admin evidence invalidates stale success, isolates captures, and publishes only after confirmed teardown', async () => {
  const directory = testDirectory('admin-evidence-test-');
  const path = join(directory, 'admin-evidence.json');
  const read = () => JSON.parse(readFileSync(path, 'utf8'));
  try {
    writeFileSync(path, '{"status":"passed","runID":"stale-run"}');
    const options = adminEvidenceOptions(directory);
    let closed = false;
    options.start = async () => {
      assert.equal(read().status, 'running');
      assert.notEqual(read().runID, 'stale-run');
      return { runID: 'a'.repeat(32), secrets: [], diagnostics() {}, close: async () => {
        assert.equal(read().status, 'running', 'Success was saved before teardown');
        closed = true;
        return { completed: true };
      } };
    };
    options.validate = async (_harness, { artifactDirectory }) => {
      writeFileSync(join(artifactDirectory, 'masked-layout.png'), 'neutral test capture');
      return { checks: ['controlled assertion'], layouts: 1 };
    };
    const first = await runAdminBrowser(options);
    assert(closed);
    assert.deepEqual(read(), first);
    assert.equal(first.status, 'passed');
    assert.equal(first.exitStatus, 0);
    assert.equal(first.teardown, 'completed');
    assert.equal(first.worktreeMatchesAtFinish, true);
    assert.deepEqual(first.worktree, await options.identity());
    assert.equal(first.invocation.declaredOuterCommand, adminCommand);
    assert.deepEqual(first.invocation.environment, { ADMIN_BROWSER_ARTIFACT_DIR: directory });
    const second = await runAdminBrowser(options);
    assert.notEqual(first.runID, second.runID);
    assert.notEqual(first.artifactDirectory, second.artifactDirectory);
    for (const run of [first, second]) assert.equal(readFileSync(join(run.artifactDirectory, 'masked-layout.png'), 'utf8'), 'neutral test capture');
    assert(!readdirSync(directory).some((name) => name.endsWith('.tmp')));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('admin evidence never certifies startup, assertion, cleanup, identity or callback failure', async (t) => {
  for (const kind of ['startup', 'assertion', 'cleanup', 'unconfirmed-cleanup', 'worktree-change', 'callback', 'private-evidence']) {
    await t.test(kind, async () => {
      const directory = testDirectory('admin-evidence-test-');
      const path = join(directory, 'admin-evidence.json');
      let closeCalls = 0;
      let interrupt;
      try {
        writeFileSync(path, '{"status":"passed","runID":"stale-run"}');
        const options = adminEvidenceOptions(directory);
        options.guard = (callback) => { interrupt = callback; return () => {}; };
        options.start = async () => {
          if (kind === 'startup') throw new Error('PRIVATE-FAILURE cookie=credential');
          return { runID: 'a'.repeat(32), secrets: ['PRIVATE-FAILURE'], diagnostics() {}, close: async () => {
            closeCalls++;
            if (kind === 'cleanup') throw new Error('PRIVATE-FAILURE body=reason');
            return kind === 'unconfirmed-cleanup' ? undefined : { completed: true };
          } };
        };
        if (kind === 'assertion') options.validate = async () => { throw new Error('PRIVATE-FAILURE payload=narrative'); };
        if (kind === 'callback') options.validate = async () => { await interrupt(); return { checks: ['must not certify'] }; };
        if (kind === 'private-evidence') options.validate = async () => ({ checks: ['PRIVATE-FAILURE'] });
        if (kind === 'worktree-change') {
          let revision = 0;
          options.identity = async () => ({ head: String(++revision).repeat(40) });
        }
        await assert.rejects(runAdminBrowser(options));
        assert.equal(closeCalls, kind === 'startup' ? 0 : 1);
        const text = readFileSync(path, 'utf8');
        const report = JSON.parse(text);
        assert.notEqual(report.runID, 'stale-run');
        assert.notEqual(report.status, 'passed');
        assert.notEqual(report.exitStatus, 0);
        assert.equal(report.status, 'failed');
        if (kind === 'cleanup' || kind === 'unconfirmed-cleanup') assert.equal(report.teardown, 'failed');
        assert.doesNotMatch(text, /PRIVATE-|cookie=|body=|payload=/);
        assert(!readdirSync(directory).some((name) => name.endsWith('.tmp')));
      } finally { rmSync(directory, { recursive: true, force: true }); }
    });
  }
  const consoleOnly = adminEvidenceOptions(null);
  consoleOnly.validate = async () => ({ checks: ['PRIVATE-FAILURE'] });
  await assert.rejects(runAdminBrowser(consoleOnly), /Private fixture data entered saved evidence/);
});

test('worker diagnostic categories cannot disclose raw exception messages', () => {
  assert.deepEqual(failureCategories('config: a PRIVATE key is required; context deadline exceeded (SQLSTATE 42501)'), ['configuration', 'key-material', 'timeout', 'sqlstate-42501']);
  assert.deepEqual(failureCategories('private narrative and subject identifiers'), []);
  assert.deepEqual(failureCategories(undefined), []);
  assert.deepEqual(failureCategories([]), []);
});

test('uncaught browser callback failures clean up and never print sensitive errors', () => {
  for (const expression of ["Promise.reject(new Error('PRIVATE cookie=secret-token'))", "queueMicrotask(() => { throw new Error('PRIVATE authorization=secret-token'); })"]) {
    const source = `import { guardBrowserFailures } from ${JSON.stringify(new URL('./portal-harness.mjs', import.meta.url).href)};
      guardBrowserFailures(async () => { process.stdout.write('cleanup finished'); });
      ${expression};`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, 'cleanup finished');
    assert.equal(result.stderr, 'Browser callback failed; sensitive exception details suppressed.\n');
  }
});

test('portal diagnostics redact secrets without treating key versions as secrets', () => {
  const signing = 's'.repeat(32);
  const replay = 'r'.repeat(32);
  const envelope = 'e'.repeat(32);
  assert.deepEqual(
    secretEnvironmentValues({
      OIDC_SIGNING_KEY_ACTIVE_PEM: signing,
      STEPUP_REPLAY_HMAC_KEY: replay,
      ENVELOPE_MASTER_KEK: envelope,
      ENVELOPE_MASTER_KEK_VERSION: '1',
      WEBAUTHN_RESIDENT_KEY: 'required',
    }),
    [signing, replay, envelope]
  );
});

test('captured fixture codes and secrets are redacted, including JSON-escaped material', () => {
  const fixture = {
    user_id: 'owned-fixture-subject',
    email: 'owned@fixture.example.test',
    credentials: [{ privateKey: 'fixture-private-key', signCount: 0 }],
    code: '004219',
    secret: 'fixture-authenticator-secret',
    otpauth_url: 'otpauth://totp/fixture?secret=fixture-authenticator-secret',
    key: 'private\nTLS\nkey',
    codes: ['one-time-recovery-code'],
    token: 'fixture-reclaim-token',
    link: 'https://localhost:43210/recover-account#token=fixture-reclaim-token',
    recipient: 'pending@fixture.example.test',
    database_url: 'postgres://fixture:private@localhost:43210/fixture',
    reason: 'controlled moderation reason',
    draft_reason: 'controlled unsent draft',
    payload_marker: 'controlled-audit-payload-marker',
    expires_at: '2026-10-25T00:00:30Z',
  };
  const secrets = fixtureSecretValues(fixture);
  assert(secrets.includes(fixture.code), 'Leading-zero TOTP codes must be kept as strings');
  assert(secrets.includes(fixture.credentials[0].privateKey));
  assert(secrets.includes(fixture.secret));
  assert(secrets.includes(fixture.key));
  assert(secrets.includes(fixture.otpauth_url));
  assert(secrets.includes(fixture.codes[0]));
  assert(secrets.includes(fixture.token));
  assert(secrets.includes(fixture.link));
  assert(secrets.includes(fixture.recipient));
  assert(secrets.includes(fixture.database_url));
  assert(secrets.includes(fixture.user_id));
  for (const value of [fixture.reason, fixture.draft_reason, fixture.payload_marker]) assert(secrets.includes(value));
  assert(secrets.includes('private'), 'Dedicated database password needs standalone redaction');
  assert(!secrets.includes(fixture.expires_at));
  const diagnostic = redactFixtureSecrets(`${JSON.stringify(fixture)}\n${secrets.join('\n')}`, secrets);
  for (const secret of secrets) {
    assert(!diagnostic.includes(secret), 'Raw private fixture value escaped redaction');
    assert(!diagnostic.includes(JSON.stringify(secret).slice(1, -1)), 'Escaped private fixture value escaped redaction');
  }
  assert(diagnostic.includes(fixture.expires_at));
  assert.deepEqual(fixtureSecretValues({ code: '', secret: null }), []);
  assert.deepEqual(fixtureRouteReferences(fixture), [fixture.user_id]);
  assert.deepEqual(fixtureRouteReferences({ user_id: 'subject', credentialId: 'credential', session_id: 'session', token: 'not-a-reference' }), ['subject', 'credential', 'session']);
});

const mailRunID = '0123456789abcdef0123456789abcdef';
const mailPolicy = {
  origin: 'https://localhost:43210',
  from: `notices@${mailRunID}.example.test`,
  recipient: `pending@${mailRunID}.example.test`,
};
const mailToken = Buffer.alloc(32, 19).toString('base64url');
function sampleMail(link = `${mailPolicy.origin}/recover-account#token=${mailToken}`) {
  const body = (media, content) => `--deletion-fixture\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Type: ${media}; charset=UTF-8\r\n\r\n${content}\r\n`;
  const encoded = link.replaceAll('=', '=3D');
  return `From: <${mailPolicy.from}>\r\nTo: <${mailPolicy.recipient}>\r\nSubject: Account deletion requested\r\nMessage-ID: <deletion.00000000-0000-4000-8000-000000000001@fixture.example.test>\r\nContent-Type: multipart/alternative; boundary="deletion-fixture"\r\n\r\n` +
    body('text/plain', `Recover until 2026-11-25T12:00:00Z (UTC)\r\n${encoded}`) +
    body('text/html', `<html lang=3D"en" dir=3D"ltr"><body><a href=3D"${encoded}">Recover account</a></body></html>`) + '--deletion-fixture--\r\n';
}

test('mail parser accepts bounded canonical fragment links and rejects leaks', () => {
  const mail = deletionMail(sampleMail(), mailPolicy);
  assert.equal(mail.token, mailToken);
  assert.equal(mail.expires_at, '2026-11-25T12:00:00Z');
  assert.deepEqual(Object.keys(mail).sort(), ['expires_at', 'link', 'locale', 'message_id', 'recipient', 'token']);
  for (const link of [
    `https://remote.example.test/recover-account#token=${mailToken}`,
    `${mailPolicy.origin}/recover-account?token=${mailToken}`,
    `${mailPolicy.origin}/recover-account#token=${mailToken}=` ,
    `${mailPolicy.origin}/recover-account#token=${'A'.repeat(42)}B`,
    `${mailPolicy.origin}/other#token=${mailToken}`,
  ]) assert.throws(() => deletionMail(sampleMail(link), mailPolicy));
  assert.throws(() => deletionMail(sampleMail().replace('Recover account</a>', 'Recover account</a><img src=3D"https://remote.example.test/pixel">'), mailPolicy));
  assert.throws(() => deletionMail(sampleMail() + 'x'.repeat(32 * 1024), mailPolicy));
});

test('quoted-printable alternatives decode UTF-8 Persian without changing canonical security values', () => {
  const encode = (value) => Array.from(Buffer.from(value, 'utf8'), (byte) => '=' + byte.toString(16).padStart(2, '0').toUpperCase()).join('');
  const prose = 'تا این مهلت می‌توانید حساب خود را بازیابی کنید: ';
  const persian = sampleMail().replace('Recover until ', encode(prose))
    .replace('lang=3D"en" dir=3D"ltr"', 'lang=3D"fa-IR" dir=3D"rtl"')
    .replace('Subject: Account deletion requested', `Subject: =?UTF-8?q?${encode('درخواست حذف حساب')}?=`);
  assert.equal(decodeQuotedPrintableUTF8(encode(prose)), prose);
  assert.equal(decodeQuotedPrintableUTF8('=D8=B3=\r\n=D9=84=D8=A7=D9=85'), 'سلام');
  const notice = deletionMail(persian, mailPolicy);
  assert.equal(notice.token, mailToken);
  assert.equal(notice.locale, 'fa-IR');
  assert.equal(notice.expires_at, '2026-11-25T12:00:00Z');
  for (const invalid of ['=FF', '=C3=28', '=D8', '=ZZ', '=0', '=', 'سلام'])
    assert.throws(() => decodeQuotedPrintableUTF8(invalid));
  assert.throws(() => deletionMail(persian.replace('2026-11-25T12:00:00Z (UTC)', '۱۴۰۵/۰۹/۰۴'), mailPolicy));
  assert.throws(() => deletionMail(persian.replace('2026-11-25T12:00:00Z (UTC)', '2026-11-25T12:00:00Z (UTC) 2026-11-26T12:00:00Z (UTC)'), mailPolicy));
});

test('owned mail sink requires verified TLS/auth, rejects foreign recipients, and captures retry identity in memory', { timeout: 15000 }, async () => {
  const directory = testDirectory('portal-mail-test-');
  let sink;
  const clients = [];
  try {
    const keyPath = join(directory, 'key.pem');
    const certPath = join(directory, 'cert.pem');
    const certificate = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-subj', '/CN=localhost', '-days', '1',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], { encoding: 'utf8', timeout: 5000 });
    assert(certificate.status === 0 && !certificate.error, 'Cannot create ephemeral test certificate');
    const cert = readFileSync(certPath);
    const secrets = [];
    sink = await startMailSink({
      ...mailPolicy, runID: mailRunID, cert, key: readFileSync(keyPath),
      username: 'fixture-user', password: 'fixture-password', onSecrets: (values) => secrets.push(...values),
    });
    const untrusted = connect({ host: '127.0.0.1', port: sink.port, rejectUnauthorized: true });
    clients.push(untrusted);
    await assert.rejects(once(untrusted, 'secureConnect'));
    const socket = connect({ host: '127.0.0.1', port: sink.port, ca: cert, minVersion: 'TLSv1.2', rejectUnauthorized: true });
    clients.push(socket);
    await once(socket, 'secureConnect');
    assert(socket.authorized, 'Fixture TLS was not verified');
    const lines = createInterface({ input: socket, crlfDelay: Infinity })[Symbol.asyncIterator]();
    const response = async () => {
      let line;
      do {
        const result = await lines.next();
        assert(!result.done, 'Fixture relay closed unexpectedly');
        line = result.value;
      } while (line[3] === '-');
      return Number(line.slice(0, 3));
    };
    const send = async (value) => { socket.write(`${value}\r\n`); return response(); };
    assert.equal(await response(), 220);
    assert.equal(await send('EHLO identity.invalid'), 250);
    assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 530);
    assert.equal(await send(`AUTH PLAIN ${Buffer.from('\0fixture-user\0wrong').toString('base64')}`), 535);
    assert.equal(await send(`AUTH PLAIN ${Buffer.from('\0fixture-user\0fixture-password').toString('base64')}`), 235);
    assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 250);
    assert.equal(await send('RCPT TO:<foreign@another.example.test>'), 550);
    assert.throws(() => sink.rejectNext('foreign@another.example.test'));
    sink.rejectNext(mailPolicy.recipient);
    for (const result of [451, 250]) {
      assert.equal(await send(`MAIL FROM:<${mailPolicy.from}>`), 250);
      assert.equal(await send(`RCPT TO:<${mailPolicy.recipient}>`), 250);
      assert.equal(await send('DATA'), 354);
      assert.equal(await send(sampleMail() + '.'), result);
    }
    const accepted = await sink.waitFor(mailPolicy.recipient);
    assert.equal(accepted.token, mailToken);
    assert.equal(sink.messages.length, 2);
    assert.equal(sink.messages[0].message_id, accepted.message_id);
    assert.equal(sink.messages[0].token, accepted.token);
    assert.equal(sink.messages[0].expires_at, accepted.expires_at);
    assert.deepEqual(sink.evidence, { tls: 1, authenticated: 1, authRejected: 1, recipientRejected: 1, temporary: 1, accepted: 1 });
    assert(secrets.includes(mailToken) && secrets.includes(accepted.link));
    await send('QUIT');
  } finally {
    for (const socket of clients) socket.destroy();
    await sink?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('fixture and replicas share one ephemeral KEK and a run-owned audit stream before migration', () => {
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  const shared = harness.slice(harness.indexOf('const storeEnv ='), harness.indexOf('const fixture ='));
  assert.match(shared, /ENVELOPE_MASTER_KEK: randomBytes\(32\)\.toString\('base64'\)/);
  assert.match(shared, /ENVELOPE_MASTER_KEK_VERSION: '1'/);
  assert.match(shared, /AUDIT_STREAM_NAME: `PORTAL_BROWSER_AUDIT_\$\{runID\}`/);
  assert.match(shared, /secrets\.push\(\.\.\.secretEnvironmentValues\(storeEnv\)\)/);
  assert.equal(harness.match(/ENVELOPE_MASTER_KEK:/g)?.length, 1);
  assert.equal(harness.match(/AUDIT_STREAM_NAME:/g)?.length, 1);
  const fixture = harness.slice(harness.indexOf('const fixture ='), harness.indexOf("fixture('migrate')"));
  assert.match(fixture, /\.\.\.storeEnv/);
  assert.match(fixture, /fixtureSecretValues\(input\)/);
  assert.match(fixture, /fixtureSecretValues\(value\)/);
  assert.match(fixture, /categories: failureCategories\(result\.stderr\)/);
  assert.doesNotMatch(fixture.replace('failureCategories(result.stderr)', ''), /result\.stderr/);
  assert.match(harness.slice(harness.indexOf('const apiEnvironment =')), /\.\.\.storeEnv/);
});

test('legal fixture diagnostics emit static categories without private error details', () => {
  const privateText = ' private@example.test private-narrative-token 123e4567-e89b-42d3-a456-426614174000';
  for (const [error, category] of [
    ['cannot create owned legal subject', 'legal-fixture-subject'],
    ['real signer did not index owned legal evidence', 'legal-fixture-signing'],
    ['owned legal publication was not acknowledged', 'legal-fixture-publication'],
  ]) assert.deepEqual(failureCategories(error + privateText), [category]);
  assert.deepEqual(failureCategories(privateText), []);
});

test('supervised log diagnostics report only fixed categories and field names', () => {
  const values = ['9007199254740993', 'private@example.test', 'PRIVATE-NARRATIVE'];
  const text = `${JSON.stringify({ seq: values[0], error: values[1], arbitrary_private_field: values[2] })}\n`;
  const summary = privateLogSummary(text, [...values, values[0]]);
  assert.deepEqual(summary, { matches: 3, kinds: { numeric: 1, identity: 1, text: 1 }, fields: ['error', 'seq'] });
  assert.doesNotMatch(JSON.stringify(summary), /PRIVATE|private@example|9007199|arbitrary_private_field/);
  assert.deepEqual(privateLogSummary('ordinary service message', values), { matches: 0, kinds: {}, fields: [] });
});

test('destructive ledger fixtures retire only a healthy, drained, cleanly exited signer', () => {
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  const stop = harness.slice(harness.indexOf('const stopSignerForDestructiveFixtures'), harness.indexOf('const setLegalLookup'));
  assert(stop.indexOf('assertHealthy();') < stop.indexOf("signer.kill('SIGTERM')"));
  assert(stop.indexOf('code === 0 && signal === null') < stop.indexOf('retired.add(signer)'));
  const browser = readFileSync(new URL('./web-admin.browser.mjs', import.meta.url), 'utf8');
  const destructive = browser.slice(browser.indexOf("checkpoint = 'admin-ledger-states'"));
  const drain = destructive.indexOf('await harness.waitForAdminDelivery();');
  const retire = destructive.indexOf('await harness.stopSignerForDestructiveFixtures();');
  assert(drain >= 0 && retire > drain && retire < destructive.indexOf("harness.fixture('admin-tamper'"));
  assert(destructive.includes('harness.assertHealthy();'));
});

test('CI preserves image/CSP coverage and gates release on the real portal suite', () => {
  const workflow = readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8');
  assert.match(workflow, /web-csp\.browser\.mjs/);
  assert.match(workflow, /smoke-image\.mjs api identity-api:ci/);
  assert.match(workflow, /nx run web:test-portal-browser --skipNxCache/);
  assert.match(workflow, /--integration-target=\$\{\{ matrix\.target \}\}/);
  assert(workflow.includes('test-portal-integration'));
  assert.match(workflow, /nx run web:test-admin-browser --skipNxCache/);
  assert.match(workflow, /needs: \[quality, security-db, security-race, frontend, portal-browser, admin-browser, registration-browser, compose-smoke\]/);
});

test('admin browser is uncached, builds its production dependencies and uses armed fixtures', () => {
  const { nx } = JSON.parse(readFileSync(new URL('../../apps/web/package.json', import.meta.url), 'utf8'));
  const target = nx.targets['test-admin-browser'];
  assert.equal(target.cache, false);
  assert.match(target.command, /web-admin\.browser\.mjs/);
  const dependencies = target.dependsOn.map((entry) => typeof entry === 'string' ? entry : entry.target);
  for (const build of ['build', 'build-portal-fixture', 'build-deletion-notifier', 'build-audit-signer', 'build-admin-audit-publisher', 'build-admin-legal'])
    assert(dependencies.includes(build));
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  assert.match(harness, /PORTAL_FIXTURE_ADMIN: admin \? '1' : '0'/);
  assert.match(harness, /APP_ENV: 'test', ADMIN_ENABLED: 'true'/);
  assert.match(harness, /LEGAL_WORKFLOW_ENABLED: 'false'/);
  assert.match(harness, /ENVELOPE_BLIND_INDEX_PEPPER: randomBytes\(32\)/);
  assert.match(harness, /const auditEnvironment = \{ \.\.\.apiEnvironment/);
  assert.match(harness, /A supervised portal process exited/);
  assert.match(harness, /return \{ runID, origin, tlsSPKI/);
  assert.doesNotMatch(harness, /console\.error\([^\n]*output/);
  assert.deepEqual(integrationTargets, ['test-security-db', 'test-admin-integration', 'test-retention-integration',
    'test-legal-workflow-integration', 'test-grpc-integration', 'test-lifecycle-integration', 'test-portal-integration']);
  const browser = readFileSync(new URL('./web-admin.browser.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(browser, /route\.fetch\s*\(/);
  assert.match(browser, /Fetch\.failRequest/);
  assert.match(browser, /guardBrowserFailures/);
  assert(browser.indexOf('await validateLegal(harness, actors, evidence') < browser.indexOf("checkpoint = 'admin-ledger-states'"));
  assert.match(browser, /mask: \[page\.locator\('[^']*\[data-legal-private\]/);
  for (const check of ['legal-audit-rollback', 'legal-lost-writes', 'legal-attribution', 'legal-revocation', 'legal-privacy'])
    assert(browser.includes(`checkpoint = '${check}'`));
  const legalFixture = readFileSync(new URL('../../apps/identity-api/cmd/portal-fixture/legal.go', import.meta.url), 'utf8');
  assert.match(legalFixture, /^\/\/go:build portalfixture\r?\n/);
  assert.match(legalFixture, /VerifyLookupFixture/);
  assert.match(legalFixture, /audit\.NewEnvelope/);
  assert.match(legalFixture, /js\.Publish/);
  assert.match(legalFixture, /ownedLegalReference/);
  assert.doesNotMatch(legalFixture, /WithLookup\(|UPDATE security_event_ledger|http\.Handle/);
});

test('portal integration cannot silently omit real dependencies or run in parallel', () => {
  const { targets } = JSON.parse(
    readFileSync(new URL('../../apps/identity-api/project.json', import.meta.url), 'utf8')
  );
  const target = targets['test-portal-integration'];
  assert.equal(target.cache, false);
  assert.equal(target.parallelism, false);
  for (const contract of [
    'DATABASE_URL',
    'REDIS_URL',
    'NATS_URL',
    'REQUIRE_PORTAL_INTEGRATION',
    'REQUIRE_PROFILE_INTEGRATION',
    '-tags=integration',
    '-p=1',
    './internal/profile',
    './internal/webauthn',
    './internal/session',
  ]) {
    assert(
      target.options.command.includes(contract),
      `Missing integration requirement ${contract}`
    );
  }
});

test('local integration inventory matches all seven mandatory CI suites in order', () => {
  const workflow = readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8');
  const job = workflow.slice(workflow.indexOf('  integration-cell:'), workflow.indexOf('  security-db:'));
  const targets = job.match(/target: \[([^\]]+)\]/)[1].split(', ');
  assert.equal(targets.length, 7);
  assert.deepEqual(integrationTargets, targets);
  assert(Object.isFrozen(integrationTargets));
  assert.match(job, /max-parallel: 1/);
  assert.match(job, /fail-fast: false/);
  assert.match(job, /timeout-minutes: 60/);
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(harness, /docker-compose\.dev|--volumes-from|--mount.*volume/);
  assert.match(harness, /outcomes\.skipped, 0/);
  assert.match(harness, /Integration service teardown was not confirmed/);
});

test('Windows admin acceptance uses an immutable production signer container and real graceful stop', () => {
  const harness = readFileSync(new URL('./portal-harness.mjs', import.meta.url), 'utf8');
  assert.match(harness, /ADMIN_BROWSER_SIGNER_IMAGE/);
  assert.match(harness, /sha256:\[0-9a-f\]\{64\}/);
  assert.match(harness, /'--network', services\.network/);
  assert.match(harness, /'--entrypoint', '\/usr\/local\/bin\/audit-signer'/);
  assert.match(harness, /docker\(\['stop', '--time', '10', signerContainer\]\)/);
  assert.match(harness, /assert\(code === 0 && signal === null/);
  assert.match(harness, /cleanup\.push\(\(\) => removeOwnedDockerResource\(ownedSigner, lifecycle\)\)/);
  assert.doesNotMatch(harness, /code === 0 \|\| signal === 'SIGTERM'/);
});

test('credential fixture is opt-in and not packaged into the production API image', () => {
  const fixture = readFileSync(
    new URL('../../apps/identity-api/cmd/portal-fixture/main.go', import.meta.url),
    'utf8'
  );
  const dockerfile = readFileSync(
    new URL('../../apps/identity-api/Dockerfile', import.meta.url),
    'utf8'
  );
  assert.match(fixture, /^\/\/go:build portalfixture\r?\n/);
  assert.match(fixture, /PORTAL_FIXTURE_ALLOW/);
  assert.match(fixture, /portal_browser_/);
  assert(!dockerfile.includes('portal-fixture') && !dockerfile.includes('portalfixture'));
});

test('integration invocation rejects all arbitrary selectors and identifies partial acceptance', () => {
  assert.deepEqual(integrationInvocation(['--integration']), { kind: 'integration', scope: 'full', targets: integrationTargets });
  for (const target of integrationTargets) assert.deepEqual(integrationInvocation([`--integration-target=${target}`]), { kind: 'integration', scope: 'partial', targets: [target] });
  for (const name of racePackages) assert.deepEqual(integrationInvocation([`--integration-race-package=${name}`]), { kind: 'race', scope: 'partial', targets: [name] });
  for (const args of [[], ['--integration', '--integration'], ['--integration-target=identity-api:test-security-db'], ['--integration-target=unknown'], ['--integration-race-package=./...'], ['--integration-race-package=./cmd/server'], ['--integration-target=test-security-db', '--run=TestOne']]) assert.throws(() => integrationInvocation(args));
});

test('all seven nonparallel targets preserve exact package inventories and serial uncached flags', () => {
  const { targets } = JSON.parse(readFileSync(new URL('../../apps/identity-api/project.json', import.meta.url)));
  for (const name of integrationTargets) {
    const target = targets[name];
    assert.equal(target.parallelism, false);
    assert.equal(target.cache, false);
    const command = target.options.command || target.options.commands.join(' ');
    const packages = [...command.matchAll(/\.\/((?:internal|cmd)\/[a-z0-9/-]+)/g)].map((match) => match[1]);
    assert.deepEqual(packages, integrationPackages[name]);
    for (const flag of ['-tags=integration', '-count=1', '-p=1']) assert(command.includes(flag));
    if (['test-security-db', 'test-retention-integration'].includes(name)) assert(command.includes('-timeout=20m'));
  }
});

test('registration target uses only immutable image and production web build, no seeded API rebuild', () => {
  const { nx } = JSON.parse(readFileSync(new URL('../../apps/web/package.json', import.meta.url)));
  const target = nx.targets['test-registration-browser'];
  assert.equal(target.cache, false);
  assert.equal(target.parallelism, false);
  assert.deepEqual(target.dependsOn, ['build']);
  assert.match(target.command, /REGISTRATION_BROWSER_API_IMAGE/);
  assert.match(target.command, /sha256:\[0-9a-f\]\{64\}/);
  assert.match(target.command, /registration-browser\.mjs/);
  const workflow = readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8');
  const job = workflow.slice(workflow.indexOf('  registration-browser:'), workflow.indexOf('  publish:'));
  assert.match(job, /needs: \[quality\]/);
  assert.match(job, /load-api/);
  assert.match(job, /verify-registration/);
  assert.doesNotMatch(job, /docker build|build-portal-fixture/);
  assert.match(job, /REGISTRATION_BROWSER_API_MANIFEST: \$\{\{ runner\.temp \}\}\/acceptance-api\/acceptance-api\.json/);
  for (const image of ['node:24-bookworm-slim', 'postgres:16-alpine', 'redis:7-alpine', 'nats:2.10-alpine']) assert(job.includes(`docker pull --platform linux/amd64 ${image}`));
  assert(job.indexOf('Preload declared registration controller') < job.indexOf('nx run web:test-registration-browser'));
  assert(job.includes("export REGISTRATION_BROWSER_CONTROLLER_IMAGE=\"$(docker image inspect --format '{{.Id}}' node:24-bookworm-slim)\""));
});

test('partial runner publishes current identities only after verified cleanup', async (t) => {
  mockPortalDocker(t);
  mockIntegrationRunner(t);
  const directory = mkdtempSync(join(tmpdir(), 'kilo', 'partial-integration-'));
  try {
    const report = await runPortalIntegrationSuites({ identify, directory, invocation: integrationInvocation(['--integration-target=test-lifecycle-integration']) });
    assert.equal(report.scope, 'partial');
    assert.equal(report.status, 'passed');
    assert.equal(report.cleanup.completed, true);
    assert.deepEqual(report.identity, fixtureIdentity);
    assert.equal(report.results.length, 1);
    assert.deepEqual(JSON.parse(readFileSync(join(directory, 'integration-test-lifecycle-integration.json'))), report);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('lifecycle catches startup and between-target signals while reserving teardown', () => {
  const lifecycle = acceptanceLifecycle({ timeout: 60_000, reserve: 10_000 });
  try {
    assert(lifecycle.remaining() <= 50_000);
    process.emit('SIGTERM');
    assert.throws(() => lifecycle.check(), /interrupted/);
    assert.doesNotThrow(() => lifecycle.check(true));
  } finally { lifecycle.release(); }
});

test('race runner invokes exact Linux CGO JSON command through Nx with one package', async (t) => {
  for (const prefix of ['github.com/hatefsystems/identity/apps/identity-api', 'identity-api', 'github.com/foreign/identity/apps/identity-api']) await t.test(prefix, async (t) => {
    const original = childProcess.spawn;
    t.mock.method(childProcess, 'spawn', (command, args, options) => {
      assert.equal(command, process.execPath);
      assert.deepEqual(args.slice(1, 6), ['exec', '-p', 'schemas', '--', 'go']);
      assert.deepEqual(args.slice(8), ['test', '-json', '-tags=integration', '-race', '-count=1', '-p=1', '-timeout=20m', './internal/mfa']);
      assert.equal(options.env.CGO_ENABLED, '1');
      assert.equal(options.env.REQUIRE_PHASE2_INTEGRATION, '1');
      const events = [{ Action: 'start', Package: `${prefix}/internal/mfa` }, { Action: 'pass', Package: `${prefix}/internal/mfa`, Test: 'TestOwned' }, { Action: 'pass', Package: `${prefix}/internal/mfa` }];
      return original(process.execPath, ['-e', `for(const event of ${JSON.stringify(events)}) console.log(JSON.stringify(event))`], options);
    });
    syncBuiltinESMExports();
    t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    if (prefix !== identityGoModule) {
      await assert.rejects(runPortalIntegrationTarget('./internal/mfa', {}), /no test evidence|failed test/);
      return;
    }
    const result = await runPortalIntegrationTarget('./internal/mfa', {});
    assert.equal(result.packages, 1);
    assert.equal(result.tests, 1);
    assert.deepEqual(result.packageEvidence, [{ package: 'github.com/hatefsystems/identity/apps/identity-api/internal/mfa', tests: ['TestOwned'] }]);
  });
});

test('normal runner admits real canonical Go headers and rejects former or foreign module prefixes', async (t) => {
  for (const prefix of ['github.com/hatefsystems/identity/apps/identity-api', 'identity-api', 'github.com/foreign/identity/apps/identity-api']) await t.test(prefix, async (t) => {
    const state = mockIntegrationRunner(t, { output(child) {
      child.stdout.emit('data', `--- PASS: TestOwnedFixture (0.01s)\nok ${prefix}/internal/lifecycle\t0.010s\n`);
    } });
    if (prefix !== identityGoModule) await assert.rejects(runPortalIntegrationTarget('test-lifecycle-integration', {}), /no test evidence|failed test/);
    else {
      const result = await runPortalIntegrationTarget('test-lifecycle-integration', {});
      assert.equal(result.target, 'identity-api:test-lifecycle-integration');
      assert.equal(result.packages, 1);
      assert.equal(result.tests, 1);
      assert.deepEqual(result.packageEvidence, [{ package: 'github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle', tests: ['TestOwnedFixture'] }]);
    }
    assert.equal(state.active, 0);
  });
});

test('successful runner exit cannot certify a surviving detached descendant with closed pipes', async (t) => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  t.after(() => Object.defineProperty(process, 'platform', platform));
  const state = mockIntegrationRunner(t);
  let alive = true;
  const signals = [];
  t.mock.method(process, 'kill', (pid, signal) => {
    assert.equal(pid, -100_000, 'Teardown targeted a foreign group');
    signals.push(signal);
    if (!alive) throw Object.assign(new Error('Gone'), { code: 'ESRCH' });
    if (signal === 'SIGKILL') alive = false;
    return true;
  });
  await assert.rejects(runPortalIntegrationTarget(integrationTargets[0], {}), /descendants outlived/);
  assert.equal(state.active, 0);
  assert(signals.includes('SIGKILL'));
  assert.equal(alive, false);
});

test('partial startup signal still attempts all registered cleanup without starting a test', async (t) => {
  const state = mockPortalDocker(t);
  const lifecycle = acceptanceLifecycle();
  t.mock.method(globalThis, 'fetch', async () => { process.emit('SIGTERM'); return { ok: true }; });
  try {
    await assert.rejects(startPortalServices({ integration: true, lifecycle }), /interrupted/);
    assert.deepEqual(state.removed, ['nats', 'redis', 'postgres', 'network']);
  } finally { lifecycle.release(); }
});

test('source changes during cleanup invalidate otherwise passing partial evidence', async (t) => {
  mockIntegrationRunner(t);
  let cleaned = false;
  await assert.rejects(runPortalIntegrationSuites({ invocation: integrationInvocation(['--integration-target=test-lifecycle-integration']),
    identify: async () => cleaned ? { ...fixtureIdentity, source: 'd'.repeat(64) } : fixtureIdentity,
    startServices: async () => ({ environment: {}, close: async () => { cleaned = true; return { completed: true }; } }),
  }), /identity mismatch/);
  assert.equal(cleaned, true);
});
