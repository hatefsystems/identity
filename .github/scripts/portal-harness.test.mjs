import assert from 'node:assert/strict';
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
  fixtureSecretValues,
  fixtureRouteReferences,
  integrationTargets,
  failureCategories,
  portalCleanup,
  portalRoute,
  redactFixtureSecrets,
  replicaFor,
  secretEnvironmentValues,
  startPortalServices,
} from './portal-harness.mjs';
import { deletionMail, startMailSink } from './portal-mail-sink.mjs';
import { adminAppearance, adminInvocation, adminWorktreeIdentity, observeAdminMarkers, observeStatusPatches, runAdminBrowser } from './web-admin.browser.mjs';
import { clean, keyStorage, runPortalBrowser, validatePortal } from './web-portal.browser.mjs';

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
  assert.equal(portalRoute('/api/v1/admin/unknown/private?token=secret'), '[redacted-route]');
  assert.equal(portalRoute('/admin/unknown/private'), '[redacted-route]');
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
    color = 'rgb(0, 0, 0)', shadow = 'rgb(0, 0, 0) 0px 0px 0px 2px', left = 0, focusedOnly = false } = {}) => {
    const style = {
      color, backgroundColor: 'rgb(255, 255, 255)', fontSize: '16px', fontWeight: '400',
      boxShadow: shadow, outlineStyle: 'none', outlineWidth: '0px', outlineColor: 'rgb(0, 0, 0)',
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
    return structuredClone(runInNewContext(`(${adminAppearance})({ focusedOnly })`, {
      focusedOnly, innerWidth: 320, innerHeight: 256, NodeFilter: { SHOW_TEXT: 4 },
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
  for (const options of [{ focused: false }, { shadow: 'none' }, { shadow: 'rgb(200, 200, 200) 0px 0px 0px 2px' }, { left: -2 }]) {
    const failures = inspect({ ...options, focusedOnly: true });
    assert(failures.length > 0);
    assert.doesNotMatch(JSON.stringify(failures), /PRIVATE-/);
  }
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
  const directory = mkdtempSync(join(tmpdir(), 'kilo', 'portal-evidence-test-'));
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
      const directory = mkdtempSync(join(tmpdir(), 'kilo', 'portal-evidence-test-'));
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

function mockPortalDocker(t, { failCleanup, failCreate, failStart } = {}) {
  const state = { created: [], started: [], removed: [], reservedPorts: 0, releasedPorts: 0, ownershipViolation: false, rejectedName: null };
  const owned = new Set();
  const bindings = new Map();
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
  t.mock.method(childProcess, 'spawnSync', (command, args) => {
    assert.equal(command, 'docker', 'Unexpected process in mocked service test');
    if (args[0] === 'network' && args[1] === 'create') {
      network = args.at(-1);
      assert.match(network, /^portal-browser-[a-f0-9]{32}$/);
      return result();
    }
    if (args[0] === 'run' || args[0] === 'create') {
      const id = args[args.indexOf('--name') + 1];
      const kind = id.split('-').at(-1);
      assert.equal(args[args.indexOf('--network') + 1], network);
      assert(args.includes(`ldp.run=${network.slice('portal-browser-'.length)}`));
      assert(args.includes(id === 'admin-test-nats' ? 'ldp.task=6.3' : 'ldp.task=7.5'));
      const ports = {};
      for (let index = 0; index < args.length; index++) {
        if (args[index] !== '--publish') continue;
        const match = args[index + 1].match(/^127\.0\.0\.1:(\d*):(\d+)$/);
        assert(match, 'A disposable port was not bound to loopback');
        ports[match[2]] = { requested: match[1], actual: Number(match[1]) || Number(match[2]) + 10_000 };
      }
      if (kind === failCreate) { state.rejectedName = id; return result(125); }
      owned.add(id);
      bindings.set(id, ports);
      state.created.push({ id, kind, operation: args[0], ports });
      return result();
    }
    if (args[0] === 'start') {
      const id = args[1];
      assert(owned.has(id));
      if (id.split('-').at(-1) === failStart) return result(125);
      state.started.push(id);
      return result();
    }
    if (args[0] === 'restart') {
      assert(owned.has(args[1]));
      for (const binding of Object.values(bindings.get(args[1]))) {
        if (!binding.requested) binding.actual++;
      }
      return result();
    }
    if (args[0] === 'inspect') {
      assert(owned.has(args[1]));
      const Ports = Object.fromEntries(Object.entries(bindings.get(args[1])).map(([port, binding]) =>
        [`${port}/tcp`, [{ HostIp: '127.0.0.1', HostPort: String(binding.actual) }]]));
      return result(0, JSON.stringify([{ NetworkSettings: { Ports } }]));
    }
    if (args[0] === 'exec') { assert(owned.has(args[1])); return result(0, 'PONG'); }
    if (args[0] === 'rm' || (args[0] === 'network' && args[1] === 'rm')) {
      const id = args.at(-1);
      const kind = args[0] === 'network' ? 'network' : id.split('-').at(-1);
      state.removed.push(kind);
      if (kind === 'network' ? id !== network : !owned.has(id)) state.ownershipViolation = true;
      return result(kind === failCleanup ? 1 : 0);
    }
    throw new Error('Unexpected mocked Docker operation');
  });
  t.mock.method(globalThis, 'fetch', async () => ({ ok: true }));
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return state;
}

test('portal cleanup preserves fresh service ownership and successful idempotent close with mocked Docker', async (t) => {
  const state = mockPortalDocker(t);
  const ids = new Set();
  for (let run = 0; run < 2; run++) {
    const services = await startPortalServices();
    assert.match(services.runID, /^[a-f0-9]{32}$/);
    ids.add(services.runID);
    assert(state.created.slice(run * 3).every(({ id }) => id.startsWith(`portal-browser-${services.runID}-`)));
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
    assert.deepEqual(state.started, [id]);
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
  const directory = mkdtempSync(join(tmpdir(), 'kilo', 'admin-evidence-test-'));
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
      const directory = mkdtempSync(join(tmpdir(), 'kilo', 'admin-evidence-test-'));
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
  return `From: <${mailPolicy.from}>\r\nTo: <${mailPolicy.recipient}>\r\nMessage-ID: <deletion.00000000-0000-4000-8000-000000000001@fixture.example.test>\r\nContent-Type: multipart/alternative; boundary="deletion-fixture"\r\n\r\n` +
    body('text/plain', `Recover until 2026-11-25T12:00:00Z (UTC)\r\n${encoded}`) +
    body('text/html', `<a href=3D"${encoded}">Recover account</a>`) + '--deletion-fixture--\r\n';
}

test('mail parser accepts bounded canonical fragment links and rejects leaks', () => {
  const mail = deletionMail(sampleMail(), mailPolicy);
  assert.equal(mail.token, mailToken);
  assert.equal(mail.expires_at, '2026-11-25T12:00:00Z');
  assert.deepEqual(Object.keys(mail).sort(), ['expires_at', 'link', 'message_id', 'recipient', 'token']);
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

test('owned mail sink requires verified TLS/auth, rejects foreign recipients, and captures retry identity in memory', { timeout: 15000 }, async () => {
  const parent = join(tmpdir(), 'kilo');
  mkdirSync(parent, { recursive: true });
  const directory = mkdtempSync(join(parent, 'portal-mail-test-'));
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
    const untrusted = connect({ host: '127.0.0.1', port: sink.port });
    clients.push(untrusted);
    await assert.rejects(once(untrusted, 'secureConnect'));
    const socket = connect({ host: '127.0.0.1', port: sink.port, ca: cert, minVersion: 'TLSv1.2' });
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
  assert.doesNotMatch(fixture, /result\.stderr/);
  assert.match(harness.slice(harness.indexOf('const apiEnvironment =')), /\.\.\.storeEnv/);
});

test('CI preserves image/CSP coverage and gates release on the real portal suite', () => {
  const workflow = readFileSync(new URL('../workflows/identity-api.yml', import.meta.url), 'utf8');
  assert.match(workflow, /web-csp\.browser\.mjs/);
  assert.match(workflow, /smoke-image\.mjs api identity-api:ci/);
  assert.match(workflow, /nx run web:test-portal-browser --skipNxCache/);
  assert.match(workflow, /nx run identity-api:test-portal-integration --skipNxCache/);
  assert.match(workflow, /nx run web:test-admin-browser --skipNxCache/);
  assert.match(workflow, /needs: \[quality, security-db, frontend, portal-browser, admin-browser\]/);
});

test('admin browser is uncached, builds its production dependencies and uses armed fixtures', () => {
  const { nx } = JSON.parse(readFileSync(new URL('../../apps/web/package.json', import.meta.url), 'utf8'));
  const target = nx.targets['test-admin-browser'];
  assert.equal(target.cache, false);
  assert.match(target.command, /web-admin\.browser\.mjs/);
  const dependencies = target.dependsOn.map((entry) => typeof entry === 'string' ? entry : entry.target);
  for (const build of ['build', 'build-portal-fixture', 'build-deletion-notifier', 'build-audit-signer', 'build-admin-audit-publisher'])
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
  assert.deepEqual(integrationTargets, ['test-security-db', 'test-admin-integration', 'test-retention-integration', 'test-lifecycle-integration', 'test-portal-integration']);
  const browser = readFileSync(new URL('./web-admin.browser.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(browser, /route\.fetch\s*\(/);
  assert.match(browser, /Fetch\.failRequest/);
  assert.match(browser, /guardBrowserFailures/);
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

test('credential fixture is opt-in and not packaged into the production API image', () => {
  const fixture = readFileSync(
    new URL('../../apps/identity-api/cmd/portal-fixture/main.go', import.meta.url),
    'utf8'
  );
  const dockerfile = readFileSync(
    new URL('../../apps/identity-api/Dockerfile', import.meta.url),
    'utf8'
  );
  assert(fixture.startsWith('//go:build portalfixture\n'));
  assert.match(fixture, /PORTAL_FIXTURE_ALLOW/);
  assert.match(fixture, /portal_browser_/);
  assert(!dockerfile.includes('portal-fixture') && !dockerfile.includes('portalfixture'));
});
