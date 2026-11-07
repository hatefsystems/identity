import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { connect as tcpConnect, createServer } from 'node:net';
import { request } from 'node:https';
import { resolve } from 'node:path';
import { connect } from 'node:tls';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import {
  assertFullEvidence,
  assertSamePhoneVerification,
  createFixtureTLS,
  decodeOwnedNatsFrames,
  installCompletionDeadlineController,
  provisionOwnedAuditStream,
  gatewayForwardTarget,
  gatewayProvisioningTarget,
  registrationGatewayTargets,
  registrationControllerUser,
  assertRegistrationAPINetwork,
  registrationStartupSummary,
  registrationBrowserDiagnostic,
  registrationPasskeyEnvironment,
  registrationChecks,
  registrationFailureDetails,
  registrationFailureMessage,
  registrationStartupFailure,
  runtimeInputs,
  startRegistrationController,
  startRegistrationGateway,
  validateGatewayTargets,
  validateSMSIRRequest,
} from './registration-browser.mjs';
import { portalCleanup } from './portal-harness.mjs';

const token = randomBytes(32).toString('base64url');

test('browser diagnostics expose only fixed routes, HTTP statuses and numeric source lines', () => {
  const privateValue = 'private-email-token-cookie';
  const error = Object.assign(new Error(privateValue), { name: 'TimeoutError',
    stack: `TimeoutError: ${privateValue}\n at startAttempt (/private/path/registration-browser.mjs:123:7)` });
  const result = registrationBrowserDiagnostic(error, {
    replies: [
      { path: '/api/v1/auth/register/start', status: 503, value: { token: privateValue } },
      { path: `/api/v1/auth/register/start?${privateValue}`, status: 401 },
      { path: '/api/v1/auth/register', status: privateValue },
      { path: '/api/v1/auth/register', status: 999 },
      null,
    ], failures: new Set(['browser-response-privacy', privateValue]),
  });
  assert.deepEqual(result, { kind: 'timeout', line: 123,
    replies: [{ path: '/api/v1/auth/register/start', status: 503 }],
    failures: ['browser-response-privacy'] });
  assert(!JSON.stringify(result).includes(privateValue));
  for (const [message, kind] of [
    [`strict mode violation: ${privateValue}`, 'ambiguous-locator'],
    [`locator.waitFor: Timeout 15000ms exceeded. ${privateValue}`, 'timeout'],
  ]) {
    const safe = registrationBrowserDiagnostic({ message, stack: privateValue });
    assert.equal(safe.kind, kind);
    assert(!JSON.stringify(safe).includes(privateValue));
  }
  assert.deepEqual(registrationBrowserDiagnostic({ stack: privateValue }),
    { kind: 'other', line: null, replies: [], failures: [] });
});
const expected = {
  apiKey: 'controller-key-not-a-provider-credential',
  templateId: 1793984,
  parameter: 'OTP',
};
const headers = {
  host: 'api.sms.ir',
  'x-api-key': expected.apiKey,
  'content-type': 'application/json',
  accept: 'application/json',
};
const payload = () => ({
  mobile: '9123456789',
  templateId: expected.templateId,
  parameters: [{ name: 'OTP', value: '000123' }],
});

const privateTargets = {
  runID: 'a'.repeat(32),
  subnet: '10.77.0.0/24',
  privateHost: '10.77.0.17',
  apiHost: '10.77.0.16',
  natsHost: '10.77.0.4',
};
test('gateway namespace reserves only collision-free IPs in the exact owned private network', () => {
  const network = {
    Id: 'f'.repeat(64),
    Internal: true,
    Labels: { 'ldp.run': privateTargets.runID },
    IPAM: { Config: [{ Subnet: privateTargets.subnet }] },
  };
  const peers = [2, 3, 4].map((part) => ({
    Id: String(part).repeat(64),
    Image: 'sha256:' + 'b'.repeat(64),
    Config: { Labels: { 'ldp.run': privateTargets.runID } },
    NetworkSettings: {
      Networks: { owned: { NetworkID: network.Id, IPAddress: `10.77.0.${part}` } },
    },
  }));
  assert.deepEqual(
    registrationGatewayTargets(privateTargets.runID, network, peers),
    privateTargets
  );
  assert.throws(
    () => registrationGatewayTargets(privateTargets.runID, { ...network, Internal: false }, peers),
    /ownership/
  );
  const foreign = structuredClone(peers);
  foreign[0].Config.Labels['ldp.run'] = 'c'.repeat(32);
  assert.throws(
    () => registrationGatewayTargets(privateTargets.runID, network, foreign),
    /ownership/
  );
  const escaped = structuredClone(peers);
  escaped[0].NetworkSettings.Networks.foreign = {
    NetworkID: 'e'.repeat(64),
    IPAddress: '192.168.1.4',
  };
  assert.throws(
    () => registrationGatewayTargets(privateTargets.runID, network, escaped),
    /ownership/
  );
  const collision = structuredClone(peers);
  collision[0].NetworkSettings.Networks.owned.IPAddress = privateTargets.apiHost;
  assert.throws(
    () => registrationGatewayTargets(privateTargets.runID, network, collision),
    /collision/
  );
});

test('gateway target validation rejects public, loopback, foreign-subnet and duplicate destinations', () => {
  assert.deepEqual(validateGatewayTargets(privateTargets), privateTargets);
  for (const apiHost of ['8.8.8.8', '127.0.0.1', '10.78.0.16', privateTargets.natsHost])
    assert.throws(() => validateGatewayTargets({ ...privateTargets, apiHost }));
  assert.throws(() => validateGatewayTargets({ ...privateTargets, runID: 'foreign' }));
  assert.throws(() =>
    validateGatewayTargets({ ...privateTargets, arbitrary: 'https://external.invalid' })
  );
});

test('gateway forwards only fixed API routes and never accepts selected hosts or CONNECT tunnels', () => {
  assert.deepEqual(gatewayForwardTarget(privateTargets, 'POST', '/api/v1/auth/register'), {
    hostname: privateTargets.apiHost,
    port: 8080,
    path: '/api/v1/auth/register',
    method: 'POST',
  });
  assert.equal(
    gatewayForwardTarget(privateTargets, 'GET', '/readyz').hostname,
    privateTargets.apiHost
  );
  for (const path of [
    'http://external.invalid/',
    '//external.invalid/',
    '/api/v1/auth/../../outside',
    '/api/v1/auth/register?target=external',
    '/private-control',
    '/v1/send/verify',
    '/api/v1/auth/\\outside',
  ])
    assert.throws(() => gatewayForwardTarget(privateTargets, 'GET', path));
  assert.throws(() => gatewayForwardTarget(privateTargets, 'CONNECT', '/api/v1/auth/register'));
});

test('gateway provisioning selects only its fixed owned NATS address and namespace', () => {
  assert.deepEqual(gatewayProvisioningTarget(privateTargets, {}), {
    address: 'nats://10.77.0.4:4222',
    runID: privateTargets.runID,
  });
  for (const body of [
    null,
    [],
    { target: 'nats://external.invalid:4222' },
    { runID: 'foreign' },
    { address: 'nats://10.77.0.16:4222' },
  ])
    assert.throws(() => gatewayProvisioningTarget(privateTargets, body));
});

test('partial gateway setup cleanup retires its controller and bridge before private services', async () => {
  const retired = [];
  const error = await registrationStartupFailure(
    'gateway-connect',
    portalCleanup([
      async () => retired.push('private-services'),
      async () => retired.push('owned-ingress'),
      async () => {
        retired.push('owned-controller');
        throw new Error('private key and provider diagnostic');
      },
    ])
  );
  assert.deepEqual(retired, ['owned-controller', 'owned-ingress', 'private-services']);
  const detail = registrationFailureDetails(error);
  assert.equal(detail.failure_check, 'gateway-connect');
  assert.equal(detail.cleanup.completed, false);
  assert(!registrationFailureMessage(error).includes('private key'));
});

test('real loopback gateway server selects only its fixed private API and strips proxy authority', async (t) => {
  const forwarded = [];
  t.mock.method(http, 'request', (options, reply) => {
    forwarded.push(options);
    const upstream = new PassThrough();
    upstream.resume();
    upstream.on('finish', () => {
      const result = Readable.from(['{"unit":true}']);
      result.statusCode = 200;
      result.headers = { 'cache-control': 'no-store' };
      reply(result);
    });
    return upstream;
  });
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  const sockets = new Set();
  const track = (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
  };
  const gateway = await startRegistrationGateway(
    {
      gateway: privateTargets,
      origin: 'https://localhost:8443',
      host: '127.0.0.1',
      gatewayPort: 0,
    },
    track
  );
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await gateway.close();
  });
  const response = await fetch(`http://127.0.0.1:${gateway.port}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'proxy-authorization': 'unit-private-value', dpop: 'unit-proof' },
    body: '{}',
  });
  assert.equal(response.status, 200);
  await response.arrayBuffer();
  assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].hostname, privateTargets.apiHost);
  assert.equal(forwarded[0].port, 8080);
  assert.equal(forwarded[0].headers['proxy-authorization'], undefined);
  assert.equal(forwarded[0].headers.host, 'localhost:8443');
  assert.equal(forwarded[0].headers['x-forwarded-proto'], 'https');
  const denied = await fetch(`http://127.0.0.1:${gateway.port}/arbitrary-target`);
  await denied.arrayBuffer();
  assert.equal(denied.status, 400);
  assert.equal(forwarded.length, 1);
});

test('gateway port collision leaves foreign listener untouched and returns classified private error', async (t) => {
  const blocker = createServer();
  blocker.listen(0, '127.0.0.1');
  await once(blocker, 'listening');
  t.after(() => new Promise((yes) => blocker.close(yes)));
  await assert.rejects(
    startRegistrationGateway(
      {
        gateway: privateTargets,
        origin: 'https://localhost:8443',
        host: '127.0.0.1',
        gatewayPort: blocker.address().port,
      },
      () => {}
    ),
    (error) =>
      registrationFailureDetails(error).failure_check === 'controller-start' &&
      !error.message.includes('EADDRINUSE')
  );
  assert.equal(blocker.listening, true);
});

test('image, artifact and manifest admission is exact and inert', () => {
  const image = 'sha256:' + 'a'.repeat(64),
    directory = resolve('unit-evidence'),
    manifest = resolve('acceptance-api.json');
  const env = {
    REGISTRATION_BROWSER_API_IMAGE: image,
    REGISTRATION_BROWSER_ARTIFACT_DIR: directory,
    REGISTRATION_BROWSER_API_MANIFEST: manifest,
  };
  assert.deepEqual(runtimeInputs(env), {
    image,
    directory,
    manifest,
    controllerImage: 'node:24-bookworm-slim',
  });
  for (const invalid of [
    '',
    'image:latest',
    'sha256:' + 'A'.repeat(64),
    'sha256:' + '0'.repeat(63),
    image + '\n',
  ]) {
    assert.throws(
      () => runtimeInputs({ ...env, REGISTRATION_BROWSER_API_IMAGE: invalid }),
      /immutable/
    );
  }
  assert.throws(() => runtimeInputs({ ...env, REGISTRATION_BROWSER_API_MANIFEST: '' }), /manifest/);
  assert.throws(
    () => runtimeInputs({ ...env, REGISTRATION_BROWSER_ARTIFACT_DIR: 'relative' }),
    /absolute/
  );
  assert.throws(() => runtimeInputs({ ...env, NODE_TLS_REJECT_UNAUTHORIZED: '0' }), /TLS/);
  assert.throws(() => runtimeInputs({ ...env, DEBUG: 'pw:protocol' }), /diagnostics/);
});

test('CLI without immutable quality image fails before any fixture work', () => {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL('./registration-browser.mjs', import.meta.url))],
    {
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
      encoding: 'utf8',
      timeout: 10000,
    }
  );
  assert.equal(result.status, 1);
  assert.equal(
    result.stdout.trim(),
    'Registration failure stage=inputs check=inputs cleanup=incomplete.'
  );
  assert.equal(
    result.stderr.trim(),
    'Registration browser acceptance failed [inputs/inputs]; private diagnostics suppressed.'
  );
});

test('startup failure preserves affirmative cleanup only after all registered disposers succeed', async () => {
  const retired = [];
  const error = await registrationStartupFailure(
    'services-images-network',
    portalCleanup([
      async () => {
        retired.push('network');
      },
      async () => {
        retired.push('container');
      },
    ])
  );
  assert.deepEqual(retired, ['container', 'network']);
  assert.deepEqual(registrationFailureDetails(error), {
    failure_stage: 'services',
    failure_check: 'services-images-network',
    cleanup: { completed: true },
  });
  assert(Object.isFrozen(error));
});

test('startup cleanup failure attempts all disposers and remains false without raw details', async () => {
  const raw =
    'private provider key SMTP body capability secret@example.test https://private.invalid/token';
  const retired = [];
  const error = await registrationStartupFailure(
    'roles',
    portalCleanup([
      async () => {
        retired.push('network');
      },
      async () => {
        retired.push('container');
        throw new Error(raw);
      },
    ])
  );
  assert.deepEqual(retired, ['container', 'network']);
  const detail = registrationFailureDetails(error);
  assert.deepEqual(detail, {
    failure_stage: 'roles',
    failure_check: 'roles',
    cleanup: { completed: false },
  });
  for (const value of [error.message, JSON.stringify(detail), registrationFailureMessage(error)])
    assert(
      !value.includes(raw) &&
        !value.includes('secret@example.test') &&
        !value.includes('private.invalid')
    );
});

test('unconfirmed helper cleanup and foreign error properties never become cleanup proof or diagnostic data', async () => {
  const incomplete = await registrationStartupFailure(
    'services-start',
    async () => ({ completed: true }),
    false
  );
  assert.equal(registrationFailureDetails(incomplete).cleanup.completed, false);
  const raw = new Error('provider key and opaque proof in error payload');
  Object.assign(raw, {
    failure_stage: 'secret@example.test',
    failure_check: 'https://private.invalid/token',
    cleanup: { completed: true },
  });
  assert.deepEqual(registrationFailureDetails(raw, 'api-ready'), {
    failure_stage: 'api',
    failure_check: 'api-ready',
    cleanup: { completed: false },
  });
  assert.deepEqual(registrationFailureDetails(raw, 'secret@example.test'), {
    failure_stage: 'unknown',
    failure_check: 'unclassified',
    cleanup: { completed: false },
  });
  assert(!registrationFailureMessage(raw).includes(raw.message));
  const unknown = await registrationStartupFailure('https://private.invalid/token', async () => ({
    completed: true,
  }));
  assert.equal(registrationFailureDetails(unknown).failure_check, 'unclassified');
});

test('NATS frames accept standard optional reply subjects and interleaved controls without consuming payload bytes', () => {
  const inbox = '_INBOX.REGISTRATION.unit',
    response = { type: 'typed', description: 'PING\r\ninside payload', unicode: 'سلام' };
  const body = Buffer.from(JSON.stringify(response));
  const message = Buffer.concat([
    Buffer.from(`MSG ${inbox} 1 _R_.response ${body.length}\r\n`),
    body,
    Buffer.from('\r\n'),
  ]);
  const prefix = Buffer.from('PONG\r\nPING\r\nINFO {"proto":1}\r\n+OK\r\n');
  const partial = decodeOwnedNatsFrames(
    Buffer.concat([prefix, message.subarray(0, message.length - 3)]),
    inbox
  );
  assert.equal(partial.pings, 1);
  assert.equal(partial.response, undefined);
  assert.equal(partial.failure, undefined);
  const final = decodeOwnedNatsFrames(
    Buffer.concat([partial.buffer, message.subarray(message.length - 3)]),
    inbox
  );
  assert.deepEqual(final.response, response);
  assert.equal(final.failure, undefined);
  assert.equal(final.buffer.length, 0);
});

test('malformed NATS frames return fixed protocol/response checks, never provider text', () => {
  const inbox = '_INBOX.REGISTRATION.unit';
  for (const wire of [
    '-ERR private@example.test secret token\r\n',
    'INFO "private@example.test"\r\n',
    `MSG foreign 1 2\r\n{}\r\n`,
    `MSG ${inbox} 2 2\r\n{}\r\n`,
    `MSG ${inbox} 1 32769\r\n`,
    `MSG ${inbox} 1 2\r\n{}xx`,
  ])
    assert.equal(decodeOwnedNatsFrames(Buffer.from(wire), inbox).failure, 'stream-protocol');
  for (const body of ['null', '[]', '0', '{bad']) {
    const frame = decodeOwnedNatsFrames(
      Buffer.from(`MSG ${inbox} 1 ${Buffer.byteLength(body)}\r\n${body}\r\n`),
      inbox
    );
    assert.equal(frame.failure, 'stream-response');
  }
});

test('partial, duplicate and unit-only checks cannot satisfy full browser evidence', () => {
  assert.throws(() => assertFullEvidence([]), /Incomplete/);
  assert.throws(() => assertFullEvidence(['unit-tests-passed']), /Incomplete/);
  assert.throws(
    () => assertFullEvidence([registrationChecks[0], registrationChecks[0]]),
    /Duplicate/
  );
  assert.throws(() => assertFullEvidence(registrationChecks.slice(0, -1)), /Incomplete/);
  assert.equal(new Set(registrationChecks).size, registrationChecks.length);
  for (const check of registrationChecks) assert.match(check, /^[a-z][a-z0-9-]+$/);
  // No unit test runs the scenario runner or emits a passed full-scope report.
});

test('OTP and pending-completion checks extend, never replace, the original inventory', () => {
  const retained = [
    'immutable-quality-image',
    'isolated-production-services',
    'packaged-migration-cleanup',
    'unicode-canonical-mailbox',
    'explicit-smtputf8-email-proof',
    'email-resend-proof-invalidation',
    'explicit-smsir-verify-contract',
    'leading-zero-otp-preserved',
    'missing-capability-denied',
    'foreign-jkt-denied',
    'wrong-browser-link-denied',
    'ownership-before-account-birth',
    'resident-uv-passkey',
    'atomic-unprivileged-account-birth',
    'fresh-discoverable-login',
    'proof-replay-denied',
    'expired-authority-denied',
    'cancel-clears-authority',
    'passkey-cancellation-no-birth',
    'unsupported-passkey-inert',
    'rate-limit-retry-after',
    'lost-completion-durable-receipt',
    'cross-tab-key-change-clears',
    'desktop-mobile-light-dark',
    'keyboard-focus-status',
    'noscript-inert',
    'proof-storage-console-network-private',
    'verified-owned-teardown',
  ];
  assert.equal(registrationChecks.length, retained.length + 2);
  for (const item of [
    ...retained,
    'corrected-otp-same-reference',
    'completion-pending-deadline-handoff',
  ])
    assert(registrationChecks.includes(item));
});

test('corrected OTP requires the original reference and no additional delivery', () => {
  const posts = [
    {
      path: '/api/v1/auth/register/phone/verify',
      body: { verification_id: 'same-proof', code: '000124' },
    },
    {
      path: '/api/v1/auth/register/phone/verify',
      body: { verification_id: 'same-proof', code: '000123' },
    },
  ];
  assertSamePhoneVerification(posts, 'same-proof', '000123', 1, 1);
  assert.throws(
    () => assertSamePhoneVerification(posts, 'different-proof', '000123', 1, 1),
    /original verification/
  );
  assert.throws(
    () => assertSamePhoneVerification(posts, 'same-proof', '000123', 1, 2),
    /another SMS/
  );
  assert.throws(
    () => assertSamePhoneVerification([], 'same-proof', '000123', 1, 1),
    /original verification/
  );
  const mixed = [
    ...posts,
    {
      path: '/api/v1/auth/register/phone/verify',
      body: { verification_id: 'new-proof', code: '000123' },
    },
  ];
  assert.throws(
    () => assertSamePhoneVerification(mixed, 'same-proof', '000123', 1, 1),
    /original verification/
  );
});

function deadlineFixture() {
  let monotonic = 1000,
    nextID = 0;
  const base = 1700000000000,
    timers = new Map();
  class BrowserDate extends Date {
    static now() {
      return base + monotonic;
    }
  }
  const performance = { now: () => monotonic };
  const crypto = { getRandomValues: (array) => array.fill(7) };
  const window = {
    setTimeout(callback, milliseconds, ...args) {
      const id = ++nextID;
      timers.set(id, { at: monotonic + Number(milliseconds), callback, args });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
  };
  const original = {
    performance: performance.now,
    timeout: window.setTimeout,
    date: BrowserDate.now,
    random: crypto.getRandomValues,
  };
  runInNewContext(`(${installCompletionDeadlineController.toString()})();`, {
    window,
    performance,
    Date: BrowserDate,
    crypto,
  });
  return {
    window,
    performance,
    BrowserDate,
    crypto,
    original,
    advance(milliseconds) {
      monotonic += milliseconds;
      for (const [id, timer] of [...timers])
        if (timer.at <= monotonic) {
          timers.delete(id);
          timer.callback(...timer.args);
        }
    },
  };
}

test('deadline controller requires actual pending monotonic samples and UI timer', () => {
  const fixture = deadlineFixture(),
    controller = fixture.window.__registrationAcceptanceDeadline;
  assert.throws(() => controller.arm(), /capture required/);
  controller.observeStart(new Date(fixture.BrowserDate.now() + 900000).toISOString());
  fixture.performance.now();
  fixture.performance.now();
  assert.throws(() => controller.arm(), /capture required/);
  assert.throws(
    () => controller.observeStart(new Date(fixture.BrowserDate.now() + 900000).toISOString()),
    /Invalid observed/
  );
  controller.restore();
});

for (const recovery of [false, true])
  test(`captured queued UI expiry callback ${recovery ? 'observes recovery handoff' : 'exposes old pending-only behavior'}`, () => {
    const fixture = deadlineFixture(),
      controller = fixture.window.__registrationAcceptanceDeadline;
    const pendingWall = fixture.BrowserDate.now() + 900000;
    controller.observeStart(new Date(pendingWall).toISOString());
    const clientDeadline = fixture.performance.now() + pendingWall - fixture.BrowserDate.now();
    let uiDeadline = fixture.performance.now() + pendingWall - fixture.BrowserDate.now(),
      callbackCalls = 0,
      cleared = false;
    const originalTimer = fixture.window.setTimeout(() => {
      callbackCalls++;
      if (fixture.performance.now() >= uiDeadline) cleared = true;
    }, pendingWall - fixture.BrowserDate.now());
    const near = controller.arm();
    assert.equal(near.uiRemaining, 8000);
    assert.equal(near.clientMaximumRemaining, 8000);
    if (recovery) uiDeadline = fixture.performance.now() + 3600000;
    // React may cancel the original timer, but an already queued task retains the
    // real application callback. The driver must execute that callback, not fake UI.
    fixture.window.clearTimeout(originalTimer);
    controller.hold(true);
    fixture.advance(9001);
    assert.equal(callbackCalls, 1);
    assert.equal(cleared, !recovery);
    assert(fixture.performance.now() > clientDeadline);
    const crossed = controller.snapshot();
    assert.equal(crossed.firedWhileHeld, 1);
    assert(crossed.uiRemaining < -1000 && crossed.clientMaximumRemaining < -1000);
    assert.equal(crossed.unchangedDate, true);
    assert.equal(crossed.unchangedRandom, true);
    assert.equal(fixture.BrowserDate.now, fixture.original.date);
    assert.equal(fixture.crypto.getRandomValues, fixture.original.random);
    controller.restore();
    assert.equal(fixture.performance.now, fixture.original.performance);
    assert.equal(fixture.window.setTimeout, fixture.original.timeout);
    assert.equal(fixture.window.__registrationAcceptanceDeadline, undefined);
  });

test('SMS.ir contract preserves six-digit strings with leading zeros', () => {
  assert.deepEqual(validateSMSIRRequest('POST', '/v1/send/verify', headers, payload(), expected), {
    mobile: '9123456789',
    code: '000123',
  });
});

for (const [name, change] of [
  [
    'wrong-method',
    (item) => {
      item.method = 'GET';
    },
  ],
  [
    'wrong-endpoint',
    (item) => {
      item.path = '/v1/send/bulk';
    },
  ],
  [
    'wrong-host',
    (item) => {
      item.headers.host = 'provider.invalid';
    },
  ],
  [
    'wrong-api-key',
    (item) => {
      item.headers['x-api-key'] = 'wrong';
    },
  ],
  [
    'missing-content-type',
    (item) => {
      delete item.headers['content-type'];
    },
  ],
  [
    'missing-accept',
    (item) => {
      delete item.headers.accept;
    },
  ],
  [
    'e164-not-national',
    (item) => {
      item.body.mobile = '+989123456789';
    },
  ],
  [
    'numeric-mobile',
    (item) => {
      item.body.mobile = 9123456789;
    },
  ],
  [
    'string-template',
    (item) => {
      item.body.templateId = String(expected.templateId);
    },
  ],
  [
    'fractional-template',
    (item) => {
      item.body.templateId = 1.2;
    },
  ],
  [
    'extra-fields',
    (item) => {
      item.body.extra = true;
    },
  ],
  [
    'extra-parameter',
    (item) => {
      item.body.parameters.push({ name: 'OTHER', value: '000123' });
    },
  ],
  [
    'decorated-parameter',
    (item) => {
      item.body.parameters[0].name = '#OTP#';
    },
  ],
  [
    'numeric-code',
    (item) => {
      item.body.parameters[0].value = 123;
    },
  ],
  [
    'short-code',
    (item) => {
      item.body.parameters[0].value = '123';
    },
  ],
  [
    'foreign-digits',
    (item) => {
      item.body.parameters[0].value = '۱۲۳۴۵۶';
    },
  ],
])
  test(`SMS.ir controller rejects ${name}`, () => {
    const item = {
      method: 'POST',
      path: '/v1/send/verify',
      headers: { ...headers },
      body: payload(),
    };
    change(item);
    assert.throws(() =>
      validateSMSIRRequest(item.method, item.path, item.headers, item.body, expected)
    );
  });

test('ephemeral Node TLS certificates bind only declared fixture names and verify CA', () => {
  const tls = createFixtureTLS(randomBytes(16).toString('hex'));
  const ca = new X509Certificate(tls.ca),
    leaf = new X509Certificate(tls.cert);
  assert.equal(ca.ca, true);
  assert.equal(leaf.ca, false);
  assert.equal(leaf.verify(ca.publicKey), true);
  assert.equal(leaf.checkHost('api.sms.ir'), 'api.sms.ir');
  assert.equal(leaf.checkHost('smtp.registration.test'), 'smtp.registration.test');
  assert.equal(leaf.checkHost('localhost'), 'localhost');
  assert.equal(leaf.checkHost('foreign.invalid'), undefined);
  assert(Date.parse(leaf.validFrom) < Date.now() && Date.parse(leaf.validTo) > Date.now());
  assert.match(tls.spki, /^[A-Za-z0-9+/]{43}=$/);
  assert.throws(() => createFixtureTLS('foreign-resource'), /ownership/);
});

function providerRequest(port, tls, body, override = {}) {
  return new Promise((yes, no) => {
    const req = request(
      {
        hostname: '127.0.0.1',
        port,
        servername: 'api.sms.ir',
        ca: tls.ca,
        method: 'POST',
        path: '/v1/send/verify',
        headers,
        timeout: 3000,
        rejectUnauthorized: true,
        ...override,
      },
      (res) => {
        const parts = [];
        res.on('data', (part) => parts.push(part));
        res.on('end', () => yes({ status: res.statusCode, body: Buffer.concat(parts).toString() }));
      }
    );
    req.on('error', no);
    req.on('timeout', () => req.destroy(new Error('Test TLS request timed out')));
    req.end(body);
  });
}
async function controlledFixture(t) {
  const tls = createFixtureTLS(randomBytes(16).toString('hex'));
  const fixture = await startRegistrationController({
    ...tls,
    ...expected,
    token,
    username: 'fixture-user',
    password: 'fixture-password',
    from: 'registration@fixture.invalid',
    origin: 'https://localhost:12345',
    providerPort: 0,
    smtpPort: 0,
    controlPort: 0,
    host: '127.0.0.1',
  });
  t.after(fixture.close);
  const control = async (path, body, authorization = `Bearer ${token}`) => {
    const response = await fetch(`http://127.0.0.1:${fixture.controlPort}${path}`, {
      method: body ? 'POST' : 'GET',
      headers: { authorization },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(3000),
    });
    return { status: response.status, value: await response.json() };
  };
  return { fixture, tls, control };
}

test('private TLS SMS controller captures only memory proof and authenticated bounded control', async (t) => {
  const { fixture, tls, control } = await controlledFixture(t);
  const response = await providerRequest(fixture.providerPort, tls, JSON.stringify(payload()));
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), { status: 1, data: { messageId: 1, cost: 0 } });
  assert.deepEqual((await control('/summary')).value, { sms: 1, mail: 0, auth: 0, violations: 0 });
  assert.equal(
    (await control('/take-sms', { mobile: payload().mobile }, 'Bearer foreign')).status,
    401
  );
  assert.deepEqual((await control('/take-sms', { mobile: payload().mobile })).value, {
    mobile: payload().mobile,
    code: '000123',
  });
  assert.equal((await control('/take-sms', { mobile: payload().mobile })).value, null);
  assert.equal((await control('/application-route', {})).status, 400);
});

test('controller TLS refuses untrusted roots and mismatched hostnames', async (t) => {
  const { fixture, tls } = await controlledFixture(t);
  await assert.rejects(providerRequest(fixture.providerPort, tls, '{}', { ca: undefined }));
  await assert.rejects(
    providerRequest(fixture.providerPort, tls, '{}', { servername: 'foreign.invalid' })
  );
});

test('malformed, oversized and redirect-shaped requests never become verified sends', async (t) => {
  const { fixture, tls, control } = await controlledFixture(t);
  assert.equal((await providerRequest(fixture.providerPort, tls, '{')).status, 400);
  assert.equal((await providerRequest(fixture.providerPort, tls, 'x'.repeat(20000))).status, 400);
  assert.equal(
    (await providerRequest(fixture.providerPort, tls, '{}', { path: '/redirect' })).status,
    400
  );
  const summary = (await control('/summary')).value;
  assert.equal(summary.sms, 0);
  assert.equal(summary.violations, 3);
});

async function smtpExchange(fixture, tls, commands) {
  const socket = connect({
    host: '127.0.0.1',
    port: fixture.smtpPort,
    servername: 'smtp.registration.test',
    ca: tls.ca,
    rejectUnauthorized: true,
  });
  await once(socket, 'secureConnect');
  socket.setEncoding('utf8');
  let buffer = '';
  const listeners = [];
  socket.on('data', (part) => {
    buffer += part;
    for (const listener of [...listeners]) listener();
  });
  const reply = () =>
    new Promise((yes, no) => {
      const timer = setTimeout(() => {
        socket.destroy();
        no(new Error('SMTP unit fixture timed out'));
      }, 3000);
      const poll = () => {
        const complete = /(?:^|\r\n)\d{3} [^\r\n]*\r\n/.exec(buffer);
        if (!complete) return;
        const end = complete.index + complete[0].length,
          value = buffer.slice(0, end);
        buffer = buffer.slice(end);
        clearTimeout(timer);
        listeners.splice(listeners.indexOf(poll), 1);
        yes(value);
      };
      listeners.push(poll);
      poll();
    });
  try {
    const replies = [await reply()];
    for (const command of commands) {
      socket.write(command + '\r\n');
      replies.push(await reply());
    }
    return replies;
  } finally {
    socket.destroy();
  }
}

test('SMTPUTF8 relay requires real TLS authentication and captures only verification fragment in memory', async (t) => {
  const { fixture, tls, control } = await controlledFixture(t);
  const attempt = randomUUID(),
    emailToken = randomBytes(32).toString('base64url');
  const link = `https://localhost:12345/register/verify-email#attempt_id=${attempt}&token=${emailToken}`;
  const auth = Buffer.from('\0fixture-user\0fixture-password').toString('base64');
  const replies = await smtpExchange(fixture, tls, [
    'EHLO unit.test',
    'AUTH PLAIN ' + auth,
    'MAIL FROM:<registration@fixture.invalid> SMTPUTF8',
    'RCPT TO:<آزمايش@example.test>',
    'DATA',
    `Subject: Verify your email for account registration\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${link}\r\n.`,
    'QUIT',
  ]);
  assert(
    replies[1].includes('SMTPUTF8') && replies[2].startsWith('235') && replies[6].startsWith('250')
  );
  const proof = (await control('/take-mail', { recipient: 'آزمايش@example.test' })).value;
  assert.deepEqual(Object.keys(proof).sort(), ['attempt_id', 'link', 'recipient', 'token']);
  assert.equal(proof.attempt_id, attempt);
  assert.equal(proof.token, emailToken);
  assert.equal(proof.link, link);
  assert.equal((await control('/take-mail', { recipient: 'آزمايش@example.test' })).value, null);
  assert.deepEqual((await control('/summary')).value, { sms: 0, mail: 1, auth: 1, violations: 0 });
});

test('SMTPUTF8 relay rejects unauthenticated sender and absent SMTPUTF8', async (t) => {
  const { fixture, tls, control } = await controlledFixture(t);
  const unauthenticated = await smtpExchange(fixture, tls, [
    'EHLO unit.test',
    'MAIL FROM:<registration@fixture.invalid> SMTPUTF8',
    'QUIT',
  ]);
  assert(unauthenticated[2].startsWith('550'));
  const auth = Buffer.from('\0fixture-user\0fixture-password').toString('base64');
  const downgraded = await smtpExchange(fixture, tls, [
    'EHLO unit.test',
    'AUTH PLAIN ' + auth,
    'MAIL FROM:<registration@fixture.invalid>',
    'QUIT',
  ]);
  assert(downgraded[3].startsWith('550'));
  assert.equal((await control('/summary')).value.mail, 0);
});

test('controller teardown destroys incomplete TLS handshakes and is idempotent', async (t) => {
  const { fixture } = await controlledFixture(t);
  const socket = tcpConnect({ host: '127.0.0.1', port: fixture.smtpPort });
  await once(socket, 'connect');
  const closed = once(socket, 'close');
  const result = await fixture.close();
  await closed;
  assert.equal(result.completed, true);
  assert.equal((await fixture.close()).completed, true);
});

test('JetStream controller refuses nonowned addresses before any connection', async () => {
  const lifecycle = { check() {}, remaining: () => 10000, signal: new AbortController().signal };
  await assert.rejects(
    provisionOwnedAuditStream('nats://foreign.invalid:4222', 'a'.repeat(32), lifecycle),
    /run-owned/
  );
  await assert.rejects(
    provisionOwnedAuditStream('nats://user:password@127.0.0.1:4222', 'a'.repeat(32), lifecycle),
    /run-owned/
  );
  await assert.rejects(
    provisionOwnedAuditStream('nats://127.0.0.1:4222', 'foreign-run', lifecycle),
    /run-owned/
  );
});

for (const { failure, reply } of [
  { failure: false, reply: false },
  { failure: true, reply: false },
  { failure: false, reply: true },
])
  test(`owned JetStream protocol controller validates ${failure ? 'rejection' : reply ? 'optional reply and control frames' : 'typed reply'}`, async (t) => {
    const runID = 'a'.repeat(32),
      stream = `REGISTRATION_${runID}`;
    let requestObserved = false;
    const sockets = new Set();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.setEncoding('utf8');
      socket.on('error', () => {});
      socket.write('INFO {"jetstream":true}\r\n');
      let buffer = '';
      socket.on('data', (part) => {
        buffer += part;
        const match =
          /PUB \$JS.API.STREAM.CREATE\.([A-Z_a-f0-9]+) (_INBOX.REGISTRATION.[a-f0-9]+) (\d+)\r\n/.exec(
            buffer
          );
        if (!match || buffer.length < match.index + match[0].length + Number(match[3]) + 2) return;
        const body = JSON.parse(
          buffer.slice(
            match.index + match[0].length,
            match.index + match[0].length + Number(match[3])
          )
        );
        requestObserved =
          match[1] === stream &&
          body.name === stream &&
          body.subjects.join(',') === 'identity.audit.registration';
        const response = JSON.stringify(
          failure
            ? { error: { code: 400 } }
            : {
                type: 'io.nats.jetstream.api.v1.stream_create_response',
                config: { name: stream, subjects: body.subjects },
              }
        );
        socket.write(
          `${reply ? 'PONG\r\nPING\r\nINFO {"proto":1}\r\n' : ''}MSG ${match[2]} 1 ${reply ? '_R_.response ' : ''}${Buffer.byteLength(response)}\r\n${response}\r\nPONG\r\n`
        );
        buffer = '';
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((yes) => server.close(yes));
    });
    const lifecycle = { check() {}, remaining: () => 10000, signal: new AbortController().signal };
    const operation = provisionOwnedAuditStream(
      `nats://127.0.0.1:${server.address().port}`,
      runID,
      lifecycle
    );
    if (failure)
      await assert.rejects(
        operation,
        (error) => registrationFailureDetails(error).failure_check === 'stream-response'
      );
    else await operation;
    assert.equal(requestObserved, true);
  });


test('private controller follows the host credential owner without DAC override or permissive TLS files', () => {
  assert.equal(registrationControllerUser(1001, 1001), '1001:1001');
  assert.equal(registrationControllerUser(0, 0), '0:0');
  assert.equal(registrationControllerUser(), `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`);
  for (const invalid of [-1, NaN, Infinity, 1.5, '1001', 4294967295]) {
    assert.throws(() => registrationControllerUser(invalid, 1001));
    assert.throws(() => registrationControllerUser(1001, invalid));
  }
});


test('API admission binds immutable network identity independent of inspect map keys', () => {
  const image = 'sha256:' + 'a'.repeat(64), network = 'b'.repeat(64), address = '10.128.20.16';
  for (const key of ['owned-network-name', network]) {
    const state = { State: { Running: true }, Image: image, NetworkSettings: { Networks: { [key]: { NetworkID: network, IPAddress: address } } } };
    assert.doesNotThrow(() => assertRegistrationAPINetwork(state, image, network, address));
    assert.throws(() => assertRegistrationAPINetwork(state, image, 'c'.repeat(64), address));
    assert.throws(() => assertRegistrationAPINetwork(state, image, network, '10.128.20.17'));
    state.NetworkSettings.Networks.extra = { NetworkID: 'd'.repeat(64), IPAddress: '10.129.20.16' };
    assert.throws(() => assertRegistrationAPINetwork(state, image, network, address));
  }
  assert.throws(() => assertRegistrationAPINetwork({ State: { Running: false } }, image, network, address),
    (error) => registrationFailureDetails(error).failure_check === 'api-running');
});

test('startup summaries expose only fixed settings and categories, never raw credentials or exceptions', () => {
  const summary = registrationStartupSummary('config: OIDC_CLIENTS_JSON invalid PRIVATE_TOKEN https://private.invalid?secret=private SQLSTATE 42501');
  assert.deepEqual(summary, { settings: ['OIDC_CLIENTS_JSON'], categories: ['configuration', 'database', 'permission'] });
  assert(!JSON.stringify(summary).includes('PRIVATE_TOKEN'));
  assert(!JSON.stringify(summary).includes('private'));
});


test('registration supplies independent production WebAuthn decoy keys without weakening resident UV policy', () => {
  const a = registrationPasskeyEnvironment('https://localhost:8443');
  const b = registrationPasskeyEnvironment('https://localhost:8443');
  assert.equal(a.WEBAUTHN_RP_ID, 'localhost');
  assert.equal(a.WEBAUTHN_RP_ORIGINS, 'https://localhost:8443');
  assert.equal(a.WEBAUTHN_RESIDENT_KEY, 'required');
  assert.equal(a.WEBAUTHN_USER_VERIFICATION, 'required');
  assert.equal(Buffer.from(a.WEBAUTHN_MOCK_CHALLENGE_KEY, 'base64').length, 32);
  assert.notEqual(a.WEBAUTHN_MOCK_CHALLENGE_KEY, b.WEBAUTHN_MOCK_CHALLENGE_KEY);
  for (const origin of ['http://localhost:8443', 'https://foreign.invalid:8443', 'https://localhost:8443/'])
    assert.throws(() => registrationPasskeyEnvironment(origin));
});
