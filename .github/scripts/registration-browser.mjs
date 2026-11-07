import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  timingSafeEqual,
  X509Certificate,
} from 'node:crypto';
import { once } from 'node:events';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { createServer as tcpServer, connect as tcpConnect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, resolve } from 'node:path';
import { createServer as tlsServer } from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  acceptanceIdentity,
  assertIdentity,
  assertRegistrationReport,
  readReport,
} from './acceptance-report.mjs';
import {
  acceptanceLifecycle,
  assertLocalOrigin,
  createOwnedDockerResource,
  removeOwnedDockerResource,
  portalCleanup,
  startPortalServices,
} from './portal-harness.mjs';
import { hashFile } from './release-images.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const script = fileURLToPath(import.meta.url);
const root = '/api/v1/auth/register';
const immutable = /^sha256:[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const capability = /^[A-Za-z0-9_-]{43}$/;
const fixed = (condition, message) => assert(condition, message);
const failureStages = Object.freeze({
  unclassified: 'unknown',
  inputs: 'inputs',
  'output-collision': 'inputs',
  identity: 'identity',
  'manifest-read': 'manifest',
  'manifest-identity': 'manifest',
  'archive-checksum': 'manifest',
  'api-image': 'image',
  'controller-image': 'image',
  'service-images': 'image',
  'web-build': 'startweb',
  'services-start': 'services',
  'services-run-id': 'services',
  'services-network': 'services',
  'services-images-network': 'services',
  'stream-address': 'stream',
  'stream-connect': 'stream',
  'stream-timeout': 'stream',
  'stream-protocol': 'stream',
  'stream-response': 'stream',
  'stream-provision': 'stream',
  'tls-material': 'tls',
  'ingress-listen': 'tls',
  'controller-create': 'controller',
  'controller-start': 'controller',
  'controller-network': 'controller',
  'controller-ready': 'controller',
  'controller-running': 'controller',
  'gateway-network': 'controller',
  'gateway-connect': 'controller',
  'gateway-targets': 'controller',
  migrate: 'migrate',
  roles: 'roles',
  'cleanup-check': 'cleanup',
  'cleanup-once': 'cleanup',
  'cleanup-expired': 'cleanup',
  'api-create': 'api',
  'api-start': 'api',
  'api-network': 'api',
  'api-running': 'api',
  'api-ready': 'api',
  'web-start': 'startweb',
  'web-ready': 'startweb',
  browser: 'browser',
  'flow-desktop-light': 'browser',
  'flow-desktop-dark': 'browser',
  'flow-mobile-light': 'browser',
  'flow-mobile-dark': 'browser',
  boundaries: 'browser',
  'provider-counts': 'browser',
  'private-logs': 'privacy',
  teardown: 'cleanup',
  'final-identity': 'identity',
  evidence: 'evidence',
  'controller-mode': 'controller',
});
const brandedFailures = new WeakSet();
const safeFailureKey = (check) =>
  typeof check === 'string' && Object.hasOwn(failureStages, check) ? check : 'unclassified';
class RegistrationFailure extends Error {
  constructor(check, completed) {
    super('Registration acceptance failed; private diagnostics suppressed.');
    const safe = safeFailureKey(check);
    this.failure_stage = failureStages[safe];
    this.failure_check = safe;
    this.cleanup = Object.freeze({ completed: completed === true });
    brandedFailures.add(this);
    Object.freeze(this);
  }
}
export function registrationFailureDetails(error, fallback = 'unclassified') {
  if (error && typeof error === 'object' && brandedFailures.has(error)) {
    return {
      failure_stage: error.failure_stage,
      failure_check: error.failure_check,
      cleanup: { completed: error.cleanup.completed === true },
    };
  }
  const safe = safeFailureKey(fallback);
  return { failure_stage: failureStages[safe], failure_check: safe, cleanup: { completed: false } };
}
export async function registrationStartupFailure(check, close, cleanupKnown = true) {
  let completed = false;
  try {
    completed = (await close())?.completed === true && cleanupKnown;
  } catch {
    completed = false;
  }
  return new RegistrationFailure(check, completed);
}
export function registrationFailureMessage(error, fallback = 'unclassified') {
  const detail = registrationFailureDetails(error, fallback);
  return `Registration browser acceptance failed [${detail.failure_stage}/${detail.failure_check}]; private diagnostics suppressed.`;
}
export const registrationChecks = Object.freeze([
  'immutable-quality-image',
  'isolated-production-services',
  'packaged-migration-cleanup',
  'unicode-canonical-mailbox',
  'explicit-smtputf8-email-proof',
  'email-resend-proof-invalidation',
  'explicit-smsir-verify-contract',
  'leading-zero-otp-preserved',
  'corrected-otp-same-reference',
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
  'completion-pending-deadline-handoff',
  'cross-tab-key-change-clears',
  'desktop-mobile-light-dark',
  'keyboard-focus-status',
  'noscript-inert',
  'proof-storage-console-network-private',
  'verified-owned-teardown',
]);

export function runtimeInputs(env = process.env) {
  fixed(
    immutable.test(env.REGISTRATION_BROWSER_API_IMAGE ?? ''),
    'An exact immutable registration API image is required'
  );
  fixed(
    typeof env.REGISTRATION_BROWSER_ARTIFACT_DIR === 'string' &&
      isAbsolute(env.REGISTRATION_BROWSER_ARTIFACT_DIR),
    'An absolute registration evidence directory is required'
  );
  const manifest =
    env.REGISTRATION_BROWSER_API_MANIFEST ||
    (env.RUNNER_TEMP && resolve(env.RUNNER_TEMP, 'acceptance-api/acceptance-api.json'));
  fixed(
    typeof manifest === 'string' && isAbsolute(manifest),
    'The checksum-bound quality API manifest is required'
  );
  fixed(
    env.NODE_TLS_REJECT_UNAUTHORIZED !== '0',
    'Registration acceptance rejects disabled TLS verification'
  );
  fixed(
    !env.DEBUG && !env.NODE_DEBUG && !env.NODE_DEBUG_NATIVE && !env.PWDEBUG,
    'Registration acceptance rejects private browser/network diagnostics'
  );
  return {
    image: env.REGISTRATION_BROWSER_API_IMAGE,
    directory: env.REGISTRATION_BROWSER_ARTIFACT_DIR,
    manifest,
    controllerImage: env.REGISTRATION_BROWSER_CONTROLLER_IMAGE || 'node:24-bookworm-slim',
  };
}

export function assertFullEvidence(checks) {
  fixed(Array.isArray(checks), 'Executed registration checks are required');
  fixed(new Set(checks).size === checks.length, 'Duplicate registration checks');
  fixed(
    checks.length === registrationChecks.length &&
      registrationChecks.every((item) => checks.includes(item)),
    'Incomplete registration browser acceptance'
  );
}

// Browser-only controller. Date, cryptography and the backend clock remain
// untouched. Queue the actual captured UI expiry callback to exercise a stale
// pending-timer task even if React cancels its original native timer on handoff.
export function installCompletionDeadlineController() {
  if (window.__registrationAcceptanceDeadline) throw new Error('Deadline controller collision');
  const nativeNow = performance.now.bind(performance);
  const originalNow = performance.now;
  const nativeDate = Date.now;
  const nativeRandom = crypto.getRandomValues;
  const nativeSet = window.setTimeout.bind(window);
  const originalSet = window.setTimeout;
  let offset = 0,
    wall = 0,
    minimum = Infinity,
    maximum = -Infinity,
    reads = 0,
    captured;
  let armed = false,
    held = false,
    queued,
    fired = 0,
    firedWhileHeld = 0;
  const now = () => nativeNow() + offset;
  Object.defineProperty(performance, 'now', {
    configurable: true,
    value: () => {
      const value = now();
      if (wall && !armed) {
        const candidate = value + wall - nativeDate();
        minimum = Math.min(minimum, candidate);
        maximum = Math.max(maximum, candidate);
        reads++;
      }
      return value;
    },
  });
  window.setTimeout = (callback, milliseconds, ...args) => {
    const duration = Number(milliseconds),
      due = now() + duration;
    if (
      wall &&
      !armed &&
      typeof callback === 'function' &&
      duration > 300000 &&
      Math.abs(due - (now() + wall - nativeDate())) < 250
    )
      captured = { callback, args, due };
    return nativeSet(callback, milliseconds, ...args);
  };
  const snapshot = () => ({
    captured: Boolean(captured),
    reads,
    armed,
    fired,
    firedWhileHeld,
    held,
    uiRemaining: captured ? captured.due - now() : null,
    clientMinimumRemaining: Number.isFinite(minimum) ? minimum - now() : null,
    clientMaximumRemaining: Number.isFinite(maximum) ? maximum - now() : null,
    unchangedDate: Date.now === nativeDate,
    unchangedRandom: crypto.getRandomValues === nativeRandom,
  });
  window.__registrationAcceptanceDeadline = {
    observeStart(expiresAt) {
      if (wall || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= nativeDate())
        throw new Error('Invalid observed pending deadline');
      wall = Date.parse(expiresAt);
    },
    arm() {
      if (
        armed ||
        !captured ||
        reads < 2 ||
        maximum - minimum > 250 ||
        Math.abs(captured.due - maximum) > 250
      )
        throw new Error('Actual pending deadline/timer capture required');
      offset = Math.min(captured.due, minimum) - nativeNow() - 8000;
      if (offset <= 0) throw new Error('Pending deadline is not safely adjustable');
      armed = true;
      const task = captured;
      queued = nativeSet(
        () => {
          fired++;
          if (held) firedWhileHeld++;
          task.callback(...task.args);
        },
        Math.max(1, task.due - now())
      );
      return snapshot();
    },
    hold(value) {
      held = value;
    },
    snapshot,
    restore() {
      if (queued !== undefined) window.clearTimeout(queued);
      Object.defineProperty(performance, 'now', { configurable: true, value: originalNow });
      window.setTimeout = originalSet;
      delete window.__registrationAcceptanceDeadline;
    },
  };
}

export function assertSamePhoneVerification(posts, verificationID, code, smsBefore, smsAfter) {
  const retries = posts.filter(
    (item) => item.path === root + '/phone/verify' && item.body.code === code
  );
  fixed(
    retries.length > 0 && retries.every((item) => item.body.verification_id === verificationID),
    'Corrected OTP did not retain its original verification reference'
  );
  fixed(smsBefore === smsAfter, 'Corrected OTP caused another SMS delivery');
}

// Minimal RFC 5280 DER for run-owned TLS fixtures, not application key custody.
// Node crypto signs the certificates; X509Certificate verifies every binding.
function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  const bytes =
    body.length < 128
      ? [body.length]
      : (() => {
          const value = [];
          let n = body.length;
          while (n) {
            value.unshift(n & 255);
            n >>>= 8;
          }
          return [128 | value.length, ...value];
        })();
  return Buffer.concat([Buffer.from([tag, ...bytes]), body]);
}
const seq = (...parts) => der(0x30, ...parts);
const oid = (value) => der(0x06, Buffer.from(value, 'hex'));
const algorithm = seq(oid('2a864886f70d01010b'), der(0x05));
const name = (value) => seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from(value)))));
const pem = (type, bytes) =>
  `-----BEGIN ${type}-----\n${bytes
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${type}-----\n`;
const extension = (id, value, critical = false) =>
  seq(oid(id), ...(critical ? [der(0x01, Buffer.from([255]))] : []), der(0x04, value));
export function createFixtureTLS(runID) {
  fixed(/^[a-f0-9]{32}$/.test(runID), 'Invalid TLS fixture ownership');
  const ca = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const leaf = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issuer = name(`registration-${runID}`);
  const time = (date) =>
    der(
      0x17,
      Buffer.from(
        date
          .toISOString()
          .replace(/[-:TZ]/g, '')
          .slice(2, 14) + 'Z'
      )
    );
  const validity = seq(time(new Date(Date.now() - 300000)), time(new Date(Date.now() + 86400000)));
  const certificate = (publicKey, subject, extensions) => {
    let serial = randomBytes(16);
    while (serial.length > 1 && serial[0] === 0) serial = serial.subarray(1);
    if (serial[0] & 128) serial = Buffer.concat([Buffer.from([0]), serial]);
    const tbs = seq(
      der(0xa0, der(0x02, Buffer.from([2]))),
      der(0x02, serial),
      algorithm,
      issuer,
      validity,
      subject,
      publicKey.export({ format: 'der', type: 'spki' }),
      der(0xa3, seq(...extensions))
    );
    return pem(
      'CERTIFICATE',
      seq(tbs, algorithm, der(0x03, Buffer.from([0]), sign('sha256', tbs, ca.privateKey)))
    );
  };
  const caPEM = certificate(ca.publicKey, issuer, [
    extension('551d13', seq(der(0x01, Buffer.from([255]))), true),
    extension('551d0f', der(0x03, Buffer.from([1, 6])), true),
  ]);
  const cert = certificate(leaf.publicKey, name('localhost'), [
    extension('551d13', seq(), true),
    extension('551d0f', der(0x03, Buffer.from([7, 128])), true),
    extension('551d25', seq(oid('2b06010505070301'))),
    extension(
      '551d11',
      seq(
        ...['localhost', 'api.sms.ir', 'smtp.registration.test'].map((host) =>
          der(0x82, Buffer.from(host))
        ),
        der(0x87, Buffer.from([127, 0, 0, 1]))
      )
    ),
  ]);
  const authority = new X509Certificate(caPEM),
    certificateInfo = new X509Certificate(cert);
  fixed(
    authority.ca &&
      certificateInfo.verify(authority.publicKey) &&
      certificateInfo.checkHost('api.sms.ir') &&
      certificateInfo.checkHost('smtp.registration.test'),
    'Run-owned TLS certificate verification failed'
  );
  return {
    ca: caPEM,
    cert,
    key: leaf.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    spki: createHash('sha256')
      .update(certificateInfo.publicKey.export({ format: 'der', type: 'spki' }))
      .digest('base64'),
  };
}

export function validateSMSIRRequest(method, path, headers, body, expected) {
  fixed(method === 'POST' && path === '/v1/send/verify', 'Unexpected SMS.ir operation');
  fixed(
    headers.host === 'api.sms.ir' &&
      headers['x-api-key'] === expected.apiKey &&
      headers['content-type'] === 'application/json' &&
      headers.accept === 'application/json',
    'SMS.ir request headers do not match the production contract'
  );
  fixed(
    body && Object.keys(body).sort().join(',') === 'mobile,parameters,templateId',
    'Unexpected SMS.ir JSON fields'
  );
  fixed(
    typeof body.mobile === 'string' &&
      /^9\d{9}$/.test(body.mobile) &&
      Number.isSafeInteger(body.templateId) &&
      body.templateId === expected.templateId,
    'Invalid SMS.ir destination or template'
  );
  fixed(
    Array.isArray(body.parameters) &&
      body.parameters.length === 1 &&
      Object.keys(body.parameters[0]).sort().join(',') === 'name,value' &&
      body.parameters[0].name === expected.parameter &&
      /^\d{6}$/.test(body.parameters[0].value),
    'SMS.ir code was not an exact six-digit string'
  );
  return { mobile: body.mobile, code: body.parameters[0].value };
}

async function boundedBody(request, limit = 16384) {
  const parts = [];
  let size = 0;
  for await (const part of request.body ?? request) {
    size += part.length;
    fixed(size <= limit, 'Fixture request exceeded its bound');
    parts.push(part);
  }
  return Buffer.concat(parts).toString('utf8');
}
const closeServer = (server) =>
  new Promise((yes, no) => {
    server.close((error) => (error ? no(error) : yes()));
    server.closeAllConnections?.();
  });
async function listen(server, port, host) {
  server.listen(port, host);
  await once(server, 'listening');
  return server.address().port;
}

function privateIPv4(value) {
  fixed(
    typeof value === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value),
    'Invalid private gateway address'
  );
  const octets = value.split('.').map(Number);
  fixed(
    octets.every((part) => part >= 0 && part <= 255) &&
      octets.join('.') === value &&
      (octets[0] === 10 ||
        (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
        (octets[0] === 192 && octets[1] === 168)),
    'Gateway destination is not private IPv4'
  );
  return octets.reduce((number, part) => number * 256 + part, 0);
}
const ipv4Text = (value) => [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
export function validateGatewayTargets(targets) {
  fixed(
    targets &&
      Object.keys(targets).sort().join(',') === 'apiHost,natsHost,privateHost,runID,subnet' &&
      /^[a-f0-9]{32}$/.test(targets.runID),
    'Invalid owned gateway namespace'
  );
  fixed(
    typeof targets.subnet === 'string' && targets.subnet.split('/').length === 2,
    'Invalid gateway subnet'
  );
  const [network, prefix] = targets.subnet.split('/'),
    bits = Number(prefix);
  fixed(/^\d+$/.test(prefix) && bits >= 8 && bits <= 27, 'Unsupported private gateway subnet');
  const base = privateIPv4(network),
    size = 2 ** (32 - bits);
  fixed(
    base % size === 0 && privateIPv4(ipv4Text(base + size - 1)) >= base,
    'Invalid private gateway subnet range'
  );
  const addresses = [targets.apiHost, targets.privateHost, targets.natsHost].map(privateIPv4);
  fixed(
    new Set(addresses).size === 3 &&
      addresses.every((address) => address > base && address < base + size - 1),
    'Gateway target escaped its owned private subnet'
  );
  return Object.freeze({ ...targets });
}
export function registrationGatewayTargets(runID, network, serviceStates) {
  fixed(
    /^[a-f0-9]{32}$/.test(runID) &&
      /^[a-f0-9]{64}$/.test(network.Id) &&
      network.Internal === true &&
      network.Labels?.['ldp.run'] === runID &&
      network.IPAM.Config.length === 1,
    'Gateway private network ownership mismatch'
  );
  const subnet = network.IPAM.Config[0].Subnet,
    base = privateIPv4(subnet.split('/')[0]);
  const services = serviceStates.map((state) => {
    fixed(
      /^[a-f0-9]{64}$/.test(state.Id) &&
        immutable.test(state.Image) &&
        state.Config.Labels?.['ldp.run'] === runID &&
        Object.keys(state.NetworkSettings.Networks).length === 1,
      'Gateway service ownership mismatch'
    );
    const peer = Object.values(state.NetworkSettings.Networks)[0];
    fixed(peer.NetworkID === network.Id, 'Gateway service network mismatch');
    return peer.IPAddress;
  });
  fixed(services.length === 3 && new Set(services).size === 3, 'Gateway services are not distinct');
  const result = validateGatewayTargets({
    runID,
    subnet,
    apiHost: ipv4Text(base + 16),
    privateHost: ipv4Text(base + 17),
    natsHost: services[2],
  });
  fixed(
    services.every(
      (host) =>
        host !== result.apiHost &&
        host !== result.privateHost &&
        privateIPv4(host) > base &&
        privateIPv4(host) < base + 2 ** (32 - Number(subnet.split('/')[1])) - 1
    ),
    'Reserved gateway address collision'
  );
  return result;
}
export function gatewayForwardTarget(targets, method, path) {
  validateGatewayTargets(targets);
  fixed(
    ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'].includes(method) &&
      typeof path === 'string' &&
      path.startsWith('/') &&
      !path.startsWith('//') &&
      !/[\\\r\n]/.test(path),
    'Unsupported gateway request'
  );
  const url = new URL(path, 'http://gateway.invalid');
  fixed(
    !url.search &&
      !url.hash &&
      (url.pathname === '/readyz' || url.pathname.startsWith('/api/v1/auth/')) &&
      url.pathname === path,
    'Gateway route is not a fixed inbound API path'
  );
  return { hostname: targets.apiHost, port: 8080, path: url.pathname, method };
}

export function gatewayProvisioningTarget(targets, body) {
  validateGatewayTargets(targets);
  fixed(
    body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0,
    'Provisioning accepts no caller-selected targets'
  );
  return { address: `nats://${targets.natsHost}:4222`, runID: targets.runID };
}

export async function startRegistrationGateway(config, track) {
  const targets = validateGatewayTargets(config.gateway);
  const gateway = httpServer((request, response) => {
    let target;
    try {
      target = gatewayForwardTarget(targets, request.method, request.url);
    } catch {
      response.writeHead(400, { 'cache-control': 'no-store' });
      response.end();
      return;
    }
    const headers = {
      ...request.headers,
      host: new URL(config.origin).host,
      'x-forwarded-proto': 'https',
      'x-forwarded-for': '127.0.0.1',
      'x-forwarded-host': new URL(config.origin).host,
    };
    for (const key of [
      'connection',
      'proxy-connection',
      'proxy-authorization',
      'proxy-authenticate',
      'upgrade',
      'te',
      'trailer',
      'transfer-encoding',
    ])
      delete headers[key];
    const upstream = httpRequest({ ...target, headers, timeout: 15000 }, (result) => {
      response.writeHead(result.statusCode, result.headers);
      result.pipe(response);
    });
    upstream.on('socket', track);
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { 'cache-control': 'no-store' });
      response.end();
    });
    request.on('aborted', () => upstream.destroy());
    request.pipe(upstream);
  });
  gateway.on('connection', track);
  try {
    return {
      port: await listen(gateway, config.gatewayPort ?? 8081, config.host || '0.0.0.0'),
      close: () => closeServer(gateway),
    };
  } catch {
    if (gateway.listening) await closeServer(gateway);
    throw new RegistrationFailure('controller-start', false);
  }
}

// This is the production-required anti-enumeration decoy key, not a mock
// authentication/provider switch. Keep it independent from every other secret.
export function registrationPasskeyEnvironment(origin) {
  assertLocalOrigin(origin);
  return {
    WEBAUTHN_RP_ID: 'localhost',
    WEBAUTHN_RP_ORIGINS: origin,
    WEBAUTHN_RP_DISPLAY_NAME: 'Registration acceptance',
    WEBAUTHN_RESIDENT_KEY: 'required',
    WEBAUTHN_USER_VERIFICATION: 'required',
    WEBAUTHN_MOCK_CHALLENGE_KEY: randomBytes(32).toString('base64'),
  };
}

// Inspect records may use a network name or ID as their map key. Identity is
// the immutable NetworkID, plus the exact count and reserved address.
export function assertRegistrationAPINetwork(state, image, networkID, address) {
  if (!state.State?.Running) throw new RegistrationFailure('api-running', false);
  const peers = Object.values(state.NetworkSettings?.Networks ?? {});
  fixed(state.Image === image && peers.length === 1 && peers[0].NetworkID === networkID &&
    peers[0].IPAddress === address, 'API escaped the owned internal network');
}

// Emit only fixed public setting names/categories, never exception text/values.
export function registrationStartupSummary(output) {
  const settings = ['APP_ENV', 'OIDC_CLIENTS_JSON', 'OIDC_ISSUER', 'SESSION_COOKIE_NAME', 'WEBAUTHN_MOCK_CHALLENGE_KEY',
    'ENVELOPE_MASTER_KEK', 'ENVELOPE_BLIND_INDEX_PEPPER', 'STEPUP_REPLAY_HMAC_KEY',
    'RECOVERY_CODES_HASH_PEPPER', 'SMS_IR_KEY_MODE', 'SMS_GATEWAY_API_KEY',
    'REGISTRATION_CLEANUP_DATABASE_URL', 'REGISTRATION_SMTP_HOST'];
  const text = String(output).slice(-65536);
  return { settings: settings.filter((name) => text.includes(name)),
    categories: ['configuration', 'database', 'redis', 'registration', 'permission', 'smtp', 'nats'].filter((name) =>
      ({ configuration: /config:/i, database: /database|postgres|sqlstate/i, redis: /redis/i,
        registration: /registration/i, permission: /permission denied|42501|EACCES/i,
        smtp: /smtp/i, nats: /nats|jetstream/i })[name].test(text)) };
}

// Public diagnostics must never copy exception messages, request bodies or URLs.
export function registrationBrowserDiagnostic(error, observed = {}) {
  const message = String(error?.message ?? '');
  const frames = String(error?.stack ?? '').split('\n').filter((frame) => !/^\s+at fixed[ (]/.test(frame)).join('\n');
  const line = Number(/registration-browser\.mjs:(\d+):\d+/.exec(frames)?.[1]);
  const paths = new Set([root, ...['start', 'email/resend', 'email/verify', 'result',
    'phone/send', 'phone/verify', 'passkey/options'].map((suffix) => `${root}/${suffix}`)]);
  return {
    kind: /strict mode violation/.test(message) ? 'ambiguous-locator'
      : error?.name === 'TimeoutError' || /\bTimeout [0-9]+ms exceeded\b/.test(message) ? 'timeout'
      : error?.code === 'ERR_ASSERTION' ? 'assertion' : 'other',
    line: Number.isSafeInteger(line) && line > 0 && line < 10000 ? line : null,
    replies: (Array.isArray(observed.replies) ? observed.replies : []).flatMap((reply) =>
      paths.has(reply?.path) && Number.isInteger(reply.status) && reply.status >= 100 && reply.status <= 599
        ? [{ path: reply.path, status: reply.status }] : []).slice(-12),
    failures: ['browser-runtime', 'browser-csp-hydration', 'browser-private-console',
      'unexpected-download', 'browser-request-privacy', 'browser-response-privacy']
      .filter((name) => observed.failures instanceof Set && observed.failures.has(name)),
  };
}

// Owner-only bind-mounted TLS material must be read by its creating host UID.
// Root with dropped DAC capabilities cannot read another user's 0700/0600 files.
export function registrationControllerUser(uid = process.getuid?.() ?? 0, gid = process.getgid?.() ?? 0) {
  fixed([uid, gid].every((value) => Number.isInteger(value) && value >= 0 && value < 4294967295), 'Invalid controller credential owner');
  return `${uid}:${gid}`;
}

// This controller is mounted only into a separately owned Node container. It is
// never an API image command, HTTP application fixture, or production provider.
export async function startRegistrationController(config) {
  fixed(
    config &&
      capability.test(config.token) &&
      config.apiKey &&
      config.username &&
      config.password &&
      Number.isSafeInteger(config.templateId),
    'Invalid private controller configuration'
  );
  if (config.gateway) validateGatewayTargets(config.gateway);
  const sockets = new Set(),
    mails = [],
    messages = [];
  const state = { sms: 0, mail: 0, auth: 0, violations: 0 };
  const track = (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.setTimeout(15000, () => socket.destroy());
    socket.on('error', () => {});
  };
  const provider = httpsServer(
    { key: config.key, cert: config.cert, minVersion: 'TLSv1.2' },
    async (request, response) => {
      try {
        const record = validateSMSIRRequest(
          request.method,
          request.url,
          request.headers,
          JSON.parse(await boundedBody(request)),
          config
        );
        fixed(messages.length < 100, 'Too many fixture messages');
        messages.push(record);
        state.sms++;
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ status: 1, data: { messageId: state.sms, cost: 0 } }));
      } catch {
        state.violations++;
        response.writeHead(400);
        response.end();
      }
    }
  );
  provider.on('connection', track);
  const smtp = tlsServer(
    { key: config.key, cert: config.cert, minVersion: 'TLSv1.2' },
    (socket) => {
      let buffer = '',
        authenticated = false,
        recipient,
        sender = false,
        data = false,
        lines = [];
      socket.setEncoding('utf8');
      socket.write('220 registration fixture ESMTP\r\n');
      socket.on('data', (chunk) => {
        buffer += chunk;
        if (buffer.length > 32768) {
          state.violations++;
          socket.destroy();
          return;
        }
        while (buffer.includes('\r\n')) {
          const end = buffer.indexOf('\r\n'),
            line = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          if (data) {
            if (line !== '.') {
              lines.push(line.replace(/^\.\./, '.'));
              if (lines.join('\r\n').length > 16384) {
                state.violations++;
                socket.destroy();
              }
              continue;
            }
            data = false;
            try {
              const body = lines.join('\r\n');
              fixed(
                authenticated && sender && recipient && mails.length < 100,
                'Unbound verification message'
              );
              const match =
                /https:\/\/localhost:\d+\/register\/verify-email#attempt_id=([a-f0-9-]{36})&token=([A-Za-z0-9_-]{43})(?:\r?\n|$)/.exec(
                  body
                );
              fixed(
                match &&
                  uuid.test(match[1]) &&
                  capability.test(match[2]) &&
                  body.includes('Subject: Verify your email for account registration'),
                'Unexpected verification message'
              );
              fixed(
                !config.origin || match[0].trim().startsWith(config.origin + '/'),
                'Foreign verification origin'
              );
              mails.push({
                recipient,
                link: match[0].trim(),
                attempt_id: match[1],
                token: match[2],
              });
              state.mail++;
              lines = [];
              recipient = undefined;
              sender = false;
              socket.write('250 accepted\r\n');
            } catch {
              state.violations++;
              socket.write('550 rejected\r\n');
            }
          } else if (/^EHLO /.test(line))
            socket.write('250-fixture\r\n250-SMTPUTF8\r\n250-8BITMIME\r\n250 AUTH PLAIN\r\n');
          else if (line.startsWith('AUTH PLAIN ')) {
            const expected = Buffer.from(`\0${config.username}\0${config.password}`),
              supplied = Buffer.from(line.slice(11), 'base64');
            authenticated =
              expected.length === supplied.length && timingSafeEqual(expected, supplied);
            supplied.fill(0);
            expected.fill(0);
            if (authenticated) {
              state.auth++;
              socket.write('235 authenticated\r\n');
            } else {
              state.violations++;
              socket.write('535 rejected\r\n');
            }
          } else if (/^MAIL FROM:/.test(line)) {
            sender =
              authenticated &&
              line.includes(`<${config.from}>`) &&
              /(?:^| )SMTPUTF8(?: |$)/.test(line);
            if (!sender) state.violations++;
            socket.write(sender ? '250 sender\r\n' : '550 sender\r\n');
          } else if (/^RCPT TO:/.test(line)) {
            const match = /^RCPT TO:<([^<>\s]+)>$/.exec(line);
            recipient = sender && match?.[1];
            socket.write(recipient ? '250 recipient\r\n' : '550 recipient\r\n');
          } else if (line === 'DATA' && recipient) {
            data = true;
            lines = [];
            socket.write('354 message\r\n');
          } else if (line === 'QUIT') socket.end('221 goodbye\r\n');
          else if (line === 'RSET') {
            sender = false;
            recipient = undefined;
            lines = [];
            socket.write('250 reset\r\n');
          } else if (line === 'NOOP') socket.write('250 ok\r\n');
          else {
            state.violations++;
            socket.write('500 unsupported\r\n');
          }
        }
      });
    }
  );
  smtp.on('connection', track);
  const control = httpServer(async (request, response) => {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'application/json');
    if (request.headers.authorization !== `Bearer ${config.token}`) {
      response.writeHead(401);
      response.end('{}');
      return;
    }
    try {
      let result;
      if (request.method === 'GET' && request.url === '/summary') result = { ...state };
      else if (request.method === 'POST' && request.url === '/provision-stream' && config.gateway) {
        const body = JSON.parse(await boundedBody(request, 128));
        const target = gatewayProvisioningTarget(config.gateway, body);
        const lifecycle = {
          check() {},
          remaining: () => 10000,
          signal: AbortSignal.timeout(10000),
        };
        await provisionOwnedAuditStream(target.address, target.runID, lifecycle, config.gateway);
        result = { provisioned: true };
      } else if (request.method === 'POST' && ['/take-mail', '/take-sms'].includes(request.url)) {
        const filter = JSON.parse(await boundedBody(request, 2048));
        const records = request.url === '/take-mail' ? mails : messages;
        const key = request.url === '/take-mail' ? 'recipient' : 'mobile';
        fixed(
          Object.keys(filter).join(',') === key && typeof filter[key] === 'string',
          'Invalid private fixture selection'
        );
        const index = records.findIndex((item) => item[key] === filter[key]);
        result = index < 0 ? null : records.splice(index, 1)[0];
      } else throw new Error('Unknown controller operation');
      response.end(JSON.stringify(result));
    } catch (error) {
      response.writeHead(400);
      const detail = registrationFailureDetails(
        error,
        request.url === '/provision-stream' ? 'stream-provision' : 'controller-ready'
      );
      response.end(
        JSON.stringify({ failure_stage: detail.failure_stage, failure_check: detail.failure_check })
      );
    }
  });
  control.on('connection', track);
  let gateway;
  const dispose = portalCleanup([
    () => closeServer(provider),
    () => closeServer(smtp),
    () => closeServer(control),
    () => gateway?.close(),
  ]);
  const close = async () => {
    for (const socket of sockets) socket.destroy();
    mails.splice(0);
    messages.splice(0);
    return dispose();
  };
  try {
    const host = config.host || '0.0.0.0';
    if (config.gateway) gateway = await startRegistrationGateway(config, track);
    return {
      providerPort: await listen(
        provider,
        config.providerPort ?? 443,
        config.gateway?.privateHost ?? host
      ),
      smtpPort: await listen(smtp, config.smtpPort ?? 465, config.gateway?.privateHost ?? host),
      controlPort: await listen(control, config.controlPort ?? 8080, host),
      gatewayPort: gateway?.port,
      close,
    };
  } catch {
    await close();
    throw new Error('Private registration controller startup failed');
  }
}

function docker(
  args,
  lifecycle,
  { teardown = false, input, timeout = 120000, includeStderr = false } = {}
) {
  lifecycle.check(teardown);
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    input,
    timeout: Math.max(1, Math.min(timeout, lifecycle.remaining(teardown))),
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  fixed(
    !result.error && result.status === 0,
    'Owned registration Docker operation failed; private diagnostics suppressed'
  );
  return result.stdout + (includeStderr ? result.stderr : '');
}
async function boundedTeardown(operation, lifecycle) {
  lifecycle.check(true);
  let timer;
  try {
    return await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error('Owned registration teardown exceeded the run deadline')),
          Math.max(1, lifecycle.remaining(true))
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function port() {
  const server = tcpServer();
  const selected = await listen(server, 0, '127.0.0.1');
  await closeServer(server);
  return selected;
}
async function waitUntil(check, lifecycle, timeout = 60000) {
  const end = Math.min(Date.now() + timeout, lifecycle.deadline - 120000);
  while (Date.now() < end) {
    lifecycle.check();
    if (await check()) return;
    await delay(100, undefined, { signal: lifecycle.signal });
  }
  throw new Error('Registration acceptance condition timed out');
}

export function decodeOwnedNatsFrames(buffer, inbox) {
  let pings = 0;
  while (buffer.length) {
    const end = buffer.indexOf('\r\n');
    if (end < 0)
      return { buffer, pings, failure: buffer.length > 4096 ? 'stream-protocol' : undefined };
    if (end > 4096) return { buffer, pings, failure: 'stream-protocol' };
    const line = buffer.subarray(0, end).toString('utf8');
    if (line === 'PING' || line === 'PONG' || line === '+OK' || line.startsWith('INFO ')) {
      if (line.startsWith('INFO ')) {
        try {
          const info = JSON.parse(line.slice(5));
          if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Error();
        } catch {
          return { buffer, pings, failure: 'stream-protocol' };
        }
      }
      if (line === 'PING') pings++;
      buffer = buffer.subarray(end + 2);
      continue;
    }
    const fields = line.split(' ');
    if (
      fields[0] !== 'MSG' ||
      ![4, 5].includes(fields.length) ||
      fields[1] !== inbox ||
      fields[2] !== '1' ||
      !/^(?:0|[1-9]\d*)$/.test(fields.at(-1))
    )
      return { buffer, pings, failure: 'stream-protocol' };
    const length = Number(fields.at(-1));
    if (!Number.isSafeInteger(length) || length > 32768)
      return { buffer, pings, failure: 'stream-protocol' };
    if (buffer.length < end + 2 + length + 2) return { buffer, pings };
    if (buffer.subarray(end + 2 + length, end + 4 + length).toString() !== '\r\n')
      return { buffer, pings, failure: 'stream-protocol' };
    try {
      const response = JSON.parse(buffer.subarray(end + 2, end + 2 + length).toString('utf8'));
      if (!response || typeof response !== 'object' || Array.isArray(response))
        return { buffer, pings, failure: 'stream-response' };
      return { buffer: buffer.subarray(end + 4 + length), pings, response };
    } catch {
      return { buffer, pings, failure: 'stream-response' };
    }
  }
  return { buffer, pings };
}

export async function provisionOwnedAuditStream(address, runID, lifecycle, privateTargets) {
  if (privateTargets) validateGatewayTargets(privateTargets);
  const url = new URL(address);
  fixed(
    url.protocol === 'nats:' &&
      (url.hostname === '127.0.0.1' ||
        (privateTargets &&
          url.hostname === privateTargets.natsHost &&
          url.port === '4222' &&
          privateTargets.runID === runID)) &&
      !url.username &&
      !url.password &&
      /^[a-f0-9]{32}$/.test(runID),
    'Only run-owned loopback NATS may be provisioned'
  );
  lifecycle.check();
  const stream = `REGISTRATION_${runID}`,
    subject = 'identity.audit.registration';
  const inbox = `_INBOX.REGISTRATION.${randomBytes(16).toString('hex')}`;
  const payload = JSON.stringify({
    name: stream,
    subjects: [subject],
    storage: 'file',
    retention: 'limits',
    max_age: 3600000000000,
    max_bytes: 16777216,
    num_replicas: 1,
  });
  return new Promise((yes, no) => {
    const socket = tcpConnect({
      host: url.hostname,
      port: Number(url.port),
      signal: lifecycle.signal,
    });
    let buffer = Buffer.alloc(0),
      sent = false,
      settled = false;
    const timer = setTimeout(
      () => finish('stream-timeout'),
      Math.min(10000, lifecycle.remaining())
    );
    const finish = (failure) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      failure ? no(new RegistrationFailure(failure, false)) : yes();
    };
    socket.on('error', () => finish('stream-connect'));
    socket.on('close', () => {
      if (!settled) finish('stream-connect');
    });
    socket.on('data', (part) => {
      buffer = Buffer.concat([buffer, part]);
      if (buffer.length > 65536) {
        finish('stream-protocol');
        return;
      }
      if (!sent) {
        const end = buffer.indexOf('\r\n');
        if (end < 0) return;
        if (end > 4096 || buffer.subarray(0, 5).toString() !== 'INFO ') {
          finish('stream-protocol');
          return;
        }
        try {
          const info = JSON.parse(buffer.subarray(5, end).toString());
          if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Error();
        } catch {
          finish('stream-protocol');
          return;
        }
        buffer = buffer.subarray(end + 2);
        sent = true;
        socket.write(
          `CONNECT {"verbose":false,"pedantic":true,"lang":"javascript","name":"registration-controller"}\r\nSUB ${inbox} 1\r\nPUB $JS.API.STREAM.CREATE.${stream} ${inbox} ${Buffer.byteLength(payload)}\r\n${payload}\r\nPING\r\n`
        );
      }
      const frame = decodeOwnedNatsFrames(buffer, inbox);
      buffer = frame.buffer;
      for (let i = 0; i < frame.pings; i++) socket.write('PONG\r\n');
      if (frame.failure) {
        finish(frame.failure);
        return;
      }
      if (!frame.response) return;
      const response = frame.response;
      finish(
        !response ||
          typeof response !== 'object' ||
          Array.isArray(response) ||
          Boolean(response.error) ||
          response.type !== 'io.nats.jetstream.api.v1.stream_create_response' ||
          response.config?.name !== stream ||
          !Array.isArray(response.config?.subjects) ||
          response.config.subjects.join(',') !== subject
          ? 'stream-response'
          : undefined
      );
    });
  });
}
const environmentArgs = (env) =>
  Object.entries(env).flatMap(([key, value]) => ['--env', `${key}=${value}`]);
const cleanEnvironment = () =>
  Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      /^(path|systemroot|windir|comspec|pathext|temp|tmp|home|userprofile|localappdata|lang)$/i.test(
        key
      )
    )
  );

async function startProductionWeb(portNumber, lifecycle) {
  lifecycle.check();
  const child = spawn(
    process.execPath,
    [
      resolve(workspace, 'node_modules/next/dist/bin/next'),
      'start',
      '--hostname',
      '127.0.0.1',
      '--port',
      String(portNumber),
    ],
    {
      cwd: resolve(workspace, 'apps/web'),
      env: { ...cleanEnvironment(), NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1' },
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    }
  );
  let output = '',
    spawnFailed = false;
  const capture = (part) => {
    output = (output + part.toString()).slice(-1048576);
  };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  child.on('error', () => {
    spawnFailed = true;
  });
  const healthy = () =>
    fixed(
      !spawnFailed && child.exitCode === null && child.signalCode === null,
      'Production web process exited'
    );
  const close = async () => {
    if (!child.pid) {
      fixed(!spawnFailed, 'Production web process failed to start');
      return;
    }
    if (process.platform === 'win32') {
      if (child.exitCode === null && child.signalCode === null) {
        const result = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
          timeout: Math.min(10000, lifecycle.remaining(true)),
          windowsHide: true,
          stdio: 'ignore',
        });
        fixed(!result.error && result.status === 0, 'Owned web descendants did not stop');
      }
    } else {
      const alive = () => {
        try {
          process.kill(-child.pid, 0);
          return true;
        } catch (error) {
          fixed(error.code === 'ESRCH', 'Cannot inspect owned web group');
          return false;
        }
      };
      if (alive()) process.kill(-child.pid, 'SIGTERM');
      const end = Math.min(Date.now() + 10000, lifecycle.deadline);
      while (alive() && Date.now() < end) await delay(50);
      if (alive()) process.kill(-child.pid, 'SIGKILL');
      const killed = Math.min(Date.now() + 5000, lifecycle.deadline);
      while (alive() && Date.now() < killed) await delay(50);
      fixed(!alive(), 'Owned web descendants survived teardown');
    }
    const end = Math.min(Date.now() + 5000, lifecycle.deadline);
    while (child.exitCode === null && child.signalCode === null && Date.now() < end)
      await delay(50);
    fixed(child.exitCode !== null || child.signalCode !== null, 'Owned web root survived teardown');
  };
  return { healthy, close, privateOutput: () => output };
}

export async function startRegistrationHarness(inputs, lifecycle, identity) {
  const cleanup = [],
    secrets = new Set(),
    containers = [];
  const remember = (value) => {
    if (typeof value === 'string' && value.length >= 6) {
      secrets.add(value);
      secrets.add(JSON.stringify(value).slice(1, -1));
    }
  };
  const dispose = portalCleanup(cleanup);
  let origin,
    web,
    apiPort,
    nextPort,
    failureCheck = 'manifest-read',
    cleanupKnown = true;
  const close = async () => {
    lifecycle.beginTeardown();
    return boundedTeardown(dispose, lifecycle);
  };
  try {
    const manifest = await readReport(inputs.manifest);
    failureCheck = 'manifest-identity';
    assertIdentity(manifest.identity, identity);
    fixed(
      manifest.schema === 1 &&
        manifest.kind === 'api' &&
        manifest.imageId === inputs.image &&
        /^[a-f0-9]{64}$/.test(manifest.sha256),
      'Quality API manifest/image mismatch'
    );
    failureCheck = 'archive-checksum';
    fixed(
      (await hashFile(resolve(dirname(inputs.manifest), 'acceptance-api.tar'))) === manifest.sha256,
      'Quality API archive checksum mismatch'
    );
    failureCheck = 'api-image';
    const [image] = JSON.parse(docker(['image', 'inspect', inputs.image], lifecycle));
    fixed(
      image.Id === inputs.image &&
        image.Os === 'linux' &&
        image.Architecture === 'amd64' &&
        image.Config.Labels?.['org.opencontainers.image.revision'] === identity.revision,
      'Immutable API image source or platform mismatch'
    );
    failureCheck = 'controller-image';
    const [controllerImage] = JSON.parse(
      docker(['image', 'inspect', inputs.controllerImage], lifecycle)
    );
    fixed(
      immutable.test(controllerImage.Id) &&
        controllerImage.Os === 'linux' &&
        controllerImage.Config.Env.some((value) => /^NODE_VERSION=24\./.test(value)),
      'Preload the declared Node 24 controller image'
    );
    failureCheck = 'service-images';
    const serviceImages = ['postgres:16-alpine', 'redis:7-alpine', 'nats:2.10-alpine'].map(
      (reference) => {
        const [image] = JSON.parse(docker(['image', 'inspect', reference], lifecycle));
        fixed(
          immutable.test(image.Id) && image.Os === 'linux',
          'Preload declared registration service images'
        );
        return image.Id;
      }
    );
    failureCheck = 'web-build';
    await access(resolve(workspace, 'apps/web/.next/BUILD_ID'));
    failureCheck = 'services-start';
    cleanupKnown = false;
    const services = await startPortalServices({ internal: true, lifecycle });
    cleanup.push(services.close);
    cleanupKnown = true;
    failureCheck = 'services-run-id';
    const { runID } = services;
    fixed(/^[a-f0-9]{32}$/.test(runID), 'Service helper returned no valid ownership identity');
    failureCheck = 'services-network';
    const [network] = JSON.parse(docker(['network', 'inspect', services.network], lifecycle));
    fixed(
      network.Internal === true &&
        network.Labels?.['ldp.run'] === runID &&
        network.IPAM.Config.length === 1,
      'Registration services are not privately owned'
    );
    failureCheck = 'services-images-network';
    const serviceNames = ['DATABASE_URL', 'REDIS_URL', 'NATS_URL'].map(
      (key) => new URL(services.internalEnvironment[key]).hostname
    );
    const serviceStates = serviceNames.map((name, index) => {
      const peer = services.privateServices?.[['postgres', 'redis', 'nats'][index]];
      fixed(
        peer && /^[a-f0-9]{64}$/.test(peer.id) && peer.hostname === name,
        'Private service handle does not match its owned internal address'
      );
      const [container] = JSON.parse(docker(['inspect', peer.id], lifecycle));
      fixed(
        container.Id === peer.id &&
          container.Config.Labels?.['ldp.run'] === runID &&
          container.Image === serviceImages[index] &&
          Object.keys(container.NetworkSettings.Networks).length === 1 &&
          container.NetworkSettings.Networks[services.network]?.NetworkID === network.Id,
        'Owned service image/network identity mismatch'
      );
      return container;
    });
    failureCheck = 'gateway-targets';
    const gatewayTargets = registrationGatewayTargets(runID, network, serviceStates);
    failureCheck = 'tls-material';
    const temporaryParent = resolve(tmpdir(), 'kilo');
    await mkdir(temporaryParent, { recursive: true });
    const temporary = await mkdtemp(resolve(temporaryParent, 'registration-browser-'));
    cleanup.push(() => rm(temporary, { recursive: true, force: true }));
    const tls = createFixtureTLS(runID);
    await writeFile(resolve(temporary, 'ca.pem'), tls.ca, { mode: 0o644 });
    await writeFile(resolve(temporary, 'cert.pem'), tls.cert, { mode: 0o644 });
    await writeFile(resolve(temporary, 'key.pem'), tls.key, { mode: 0o600 });
    remember(tls.key);
    nextPort = await port();
    const ingress = httpsServer(
      { key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' },
      (request, response) => {
        if (lifecycle.signal.aborted) {
          response.writeHead(503);
          response.end();
          return;
        }
        if (!origin || request.headers.host !== new URL(origin).host) {
          response.writeHead(421);
          response.end();
          return;
        }
        const path = new URL(request.url, origin).pathname;
        const upstream = httpRequest(
          {
            hostname: '127.0.0.1',
            port: path.startsWith('/api/') ? apiPort : nextPort,
            method: request.method,
            path: request.url,
            timeout: 15000,
            headers: {
              ...request.headers,
              host: new URL(origin).host,
              'x-forwarded-for': '127.0.0.1',
              'x-forwarded-proto': 'https',
              'x-forwarded-host': new URL(origin).host,
            },
          },
          (result) => {
            response.writeHead(result.statusCode, result.headers);
            result.pipe(response);
          }
        );
        upstream.on('timeout', () => upstream.destroy());
        upstream.on('error', () => {
          if (!response.headersSent)
            response.writeHead(502, { 'cache-control': 'private, no-store' });
          response.end();
        });
        request.on('aborted', () => upstream.destroy());
        request.pipe(upstream);
      }
    );
    const ingressSockets = new Set();
    ingress.on('connection', (socket) => {
      ingressSockets.add(socket);
      socket.on('close', () => ingressSockets.delete(socket));
      socket.setTimeout(15000, () => socket.destroy());
    });
    failureCheck = 'ingress-listen';
    await listen(ingress, 0, '127.0.0.1');
    cleanup.push(() => {
      for (const socket of ingressSockets) socket.destroy();
      return closeServer(ingress);
    });
    origin = `https://localhost:${ingress.address().port}`;
    const apiKey = randomBytes(32).toString('hex'),
      token = randomBytes(32).toString('base64url'),
      username = randomBytes(24).toString('hex'),
      password = randomBytes(32).toString('hex');
    for (const value of [apiKey, token, username, password]) remember(value);
    remember(Buffer.from(`\0${username}\0${password}`).toString('base64'));
    const controllerEnv = {
      REGISTRATION_CONTROLLER_RUN_ID: runID,
      REGISTRATION_CONTROLLER_TOKEN: token,
      REGISTRATION_CONTROLLER_API_KEY: apiKey,
      REGISTRATION_CONTROLLER_USERNAME: username,
      REGISTRATION_CONTROLLER_PASSWORD: password,
      REGISTRATION_CONTROLLER_FROM: 'registration@fixture.invalid',
      REGISTRATION_CONTROLLER_ORIGIN: origin,
      REGISTRATION_CONTROLLER_GATEWAY: JSON.stringify(gatewayTargets),
    };
    failureCheck = 'gateway-network';
    const gatewayNetwork = createOwnedDockerResource(
      'network',
      ['--label', 'ldp.task=registration-browser', `registration-${runID}-ingress`],
      runID,
      lifecycle
    );
    cleanup.push(() => removeOwnedDockerResource(gatewayNetwork, lifecycle));
    const [externalNetwork] = JSON.parse(
      docker(['network', 'inspect', gatewayNetwork.id], lifecycle)
    );
    fixed(
      externalNetwork.Internal === false &&
        externalNetwork.Labels?.['ldp.run'] === runID &&
        externalNetwork.Id === gatewayNetwork.id,
      'Gateway ingress network ownership mismatch'
    );
    const createContainer = (
      suffix,
      args,
      imageID = inputs.image,
      env = {},
      command = [],
      containerNetwork = services.network
    ) => {
      const owned = createOwnedDockerResource(
        'container',
        [
          '--name',
          `registration-${runID}-${suffix}`,
          '--network',
          containerNetwork,
          '--label',
          'ldp.task=registration-browser',
          ...args,
          ...environmentArgs(env),
          imageID,
          ...command,
        ],
        runID,
        lifecycle
      );
      cleanup.push(() => removeOwnedDockerResource(owned, lifecycle));
      containers.push(owned);
      return owned;
    };
    failureCheck = 'controller-create';
    const ownedController = createContainer(
      'controller',
      [
        '--publish',
        '127.0.0.1::8080',
        '--publish',
        '127.0.0.1::8081',
        '--user',
        registrationControllerUser(),
        '--cap-drop',
        'ALL',
        '--cap-add',
        'NET_BIND_SERVICE',
        '--read-only',
        '--mount',
        `type=bind,source=${dirname(script)},target=/scripts,readonly`,
        '--mount',
        `type=bind,source=${temporary},target=/certs,readonly`,
        '--entrypoint',
        'node',
      ],
      controllerImage.Id,
      controllerEnv,
      ['/scripts/registration-browser.mjs', '--controller'],
      gatewayNetwork.id
    );
    failureCheck = 'gateway-connect';
    docker(
      [
        'network',
        'connect',
        '--ip',
        gatewayTargets.privateHost,
        '--alias',
        'api.sms.ir',
        '--alias',
        'smtp.registration.test',
        network.Id,
        ownedController.id,
      ],
      lifecycle
    );
    failureCheck = 'controller-start';
    docker(['start', ownedController.id], lifecycle);
    const [controllerState] = JSON.parse(docker(['inspect', ownedController.id], lifecycle));
    failureCheck = 'controller-network';
    fixed(
      Object.keys(controllerState.NetworkSettings.Networks).length === 2 &&
        controllerState.NetworkSettings.Networks[services.network]?.NetworkID === network.Id &&
        controllerState.NetworkSettings.Networks[services.network]?.IPAddress ===
          gatewayTargets.privateHost &&
        Object.values(controllerState.NetworkSettings.Networks).some(
          (peer) => peer.NetworkID === gatewayNetwork.id
        ),
      'Controller does not have exactly its owned private and ingress networks'
    );
    const bindings = [8080, 8081].map(
      (port) => controllerState.NetworkSettings.Ports[`${port}/tcp`]
    );
    fixed(
      bindings.every(
        (records) =>
          records?.length === 1 &&
          records[0].HostIp === '127.0.0.1' &&
          Number(records[0].HostPort) > 0
      ),
      'Gateway published ports are not owned loopback bindings'
    );
    const controllerPort = Number(bindings[0][0].HostPort);
    apiPort = Number(bindings[1][0].HostPort);
    const control = async (path, body) => {
      lifecycle.check();
      const response = await fetch(`http://127.0.0.1:${controllerPort}${path}`, {
        method: body ? 'POST' : 'GET',
        headers: {
          authorization: `Bearer ${token}`,
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.any([
          lifecycle.signal,
          AbortSignal.timeout(path === '/provision-stream' ? 15000 : 5000),
        ]),
        redirect: 'error',
      });
      const result = JSON.parse(await boundedBody(response, 16384));
      if (!response.ok) {
        const check =
          result &&
          typeof result.failure_check === 'string' &&
          failureStages[result.failure_check] === 'stream'
            ? result.failure_check
            : 'controller-ready';
        throw new RegistrationFailure(check, false);
      }
      return result;
    };
    failureCheck = 'controller-ready';
    await waitUntil(async () => {
      const [state] = JSON.parse(docker(['inspect', ownedController.id], lifecycle));
      if (!state.State.Running) throw new RegistrationFailure('controller-running', false);
      try {
        return (await control('/summary')).violations === 0;
      } catch {
        return false;
      }
    }, lifecycle);
    failureCheck = 'stream-provision';
    fixed(
      (await control('/provision-stream', {})).provisioned === true,
      'Private controller did not provision its exact owned audit stream'
    );
    const packaged = (suffix, command, args, env) => {
      const owned = createOwnedDockerResource(
        'container',
        [
          '--name',
          `registration-${runID}-${suffix}`,
          '--network',
          network.Id,
          '--entrypoint',
          `/usr/local/bin/${command}`,
          ...environmentArgs(env),
          inputs.image,
          ...args,
        ],
        runID,
        lifecycle
      );
      cleanup.push(() => removeOwnedDockerResource(owned, lifecycle));
      containers.push(owned);
      docker(['start', owned.id], lifecycle);
      docker(['wait', owned.id], lifecycle, { timeout: 60000 });
      const [state] = JSON.parse(docker(['inspect', owned.id], lifecycle));
      fixed(state.Image === inputs.image && state.State.ExitCode === 0, 'Packaged command failed');
    };
    failureCheck = 'migrate';
    packaged('migrate', 'migrate', ['up'], {
      APP_ENV: 'production',
      DATABASE_URL: services.internalEnvironment.DATABASE_URL,
    });
    const postgres = new URL(services.internalEnvironment.DATABASE_URL),
      database = postgres.pathname.slice(1);
    const sql = (query) =>
      docker(
        [
          'exec',
          '-i',
          serviceStates[0].Id,
          'psql',
          '--no-psqlrc',
          '--quiet',
          '--tuples-only',
          '--no-align',
          '-v',
          'ON_ERROR_STOP=1',
          '-U',
          'portal',
          '-d',
          database,
        ],
        lifecycle,
        { input: query }
      ).trim();
    const apiPassword = randomBytes(24).toString('hex'),
      cleanupPassword = randomBytes(24).toString('hex');
    remember(apiPassword);
    remember(cleanupPassword);
    failureCheck = 'roles';
    sql(`CREATE ROLE registration_api LOGIN NOINHERIT PASSWORD '${apiPassword}'; CREATE ROLE registration_cleanup LOGIN NOINHERIT PASSWORD '${cleanupPassword}';
GRANT USAGE ON SCHEMA public TO registration_api,registration_cleanup;
GRANT SELECT,INSERT,UPDATE ON public.users,public.webauthn_credentials TO registration_api;
GRANT SELECT ON public.roles,public.permissions,public.role_permissions,public.user_roles TO registration_api;
GRANT USAGE,SELECT ON SEQUENCE public.account_auth_epoch_seq TO registration_api;
GRANT SELECT,INSERT ON public.event_outbox TO registration_api;
GRANT SELECT,INSERT ON public.registration_attempts TO registration_api;
GRANT UPDATE(details_encrypted,email_token_hash,email_token_issued_at,email_token_expires_at,email_verified_at,sms_verification_ref,phone_verified_at,challenge_revision,row_revision,passkey_created_at,passkey_expires_at,state,terminal_at,receipt_expires_at,completion_fingerprint,result_user_id) ON public.registration_attempts TO registration_api;
GRANT SELECT,DELETE ON public.registration_attempts TO registration_cleanup; GRANT SELECT ON public.legal_holds TO registration_cleanup;`);
    const connection = (user, pass) => {
      const url = new URL(postgres);
      url.username = user;
      url.password = pass;
      return url.href;
    };
    const cleanupDSN = connection('registration_cleanup', cleanupPassword);
    const cleanupEnv = {
      APP_ENV: 'production',
      REGISTRATION_CLEANUP_DATABASE_URL: cleanupDSN,
      REGISTRATION_CLEANUP_BATCH_SIZE: '100',
    };
    failureCheck = 'cleanup-check';
    packaged('cleanup-check', 'registration-cleanup', ['check'], cleanupEnv);
    failureCheck = 'cleanup-once';
    packaged('cleanup-once', 'registration-cleanup', ['once'], cleanupEnv);
    const key = () =>
      generateKeyPairSync('ec', { namedCurve: 'P-256' })
        .privateKey.export({ type: 'pkcs8', format: 'pem' })
        .toString();
    const env = {
      ...services.internalEnvironment,
      ...cleanupEnv,
      DATABASE_URL: connection('registration_api', apiPassword),
      HOST: '0.0.0.0',
      PORT: '8080',
      PORTAL_ORIGIN: origin,
      OIDC_ISSUER: origin,
      OIDC_SIGNING_KEY_ACTIVE_PEM: key(),
      OIDC_SIGNING_KEY_NEXT_PEM: key(),
      OIDC_CLIENTS_JSON: JSON.stringify([
        {
          client_id: 'registration-browser',
          redirect_uris: [origin + '/callback'],
          token_endpoint_auth_method: 'none',
          allowed_scopes: ['openid', 'profile'],
        },
      ]),
      ...registrationPasskeyEnvironment(origin),
      ENVELOPE_MASTER_KEK: randomBytes(32).toString('base64'),
      ENVELOPE_MASTER_KEK_VERSION: '1',
      ENVELOPE_BLIND_INDEX_PEPPER: randomBytes(32).toString('base64'),
      ENVELOPE_BLIND_INDEX_PEPPER_VERSION: '1',
      STEPUP_REPLAY_HMAC_KEY: randomBytes(32).toString('base64'),
      RECOVERY_CODES_HASH_PEPPER: randomBytes(32).toString('base64'),
      AUDIT_STREAM_NAME: `REGISTRATION_${runID}`,
      AUDIT_SUBJECT: 'identity.audit.registration',
      SESSION_COOKIE_NAME: '__Host-session',
      SESSION_COOKIE_SECURE: 'true',
      SESSION_ABSOLUTE_TTL: '2h',
      SESSION_IDLE_TTL: '30m',
      TRUSTED_PROXY_CIDRS: `${gatewayTargets.privateHost}/32`,
      ADMIN_ENABLED: 'false',
      LEGAL_WORKFLOW_ENABLED: 'false',
      GRPC_ENABLED: 'false',
      GDPR_DELETION_ENABLED: 'false',
      REGISTRATION_ENABLED: 'true',
      REGISTRATION_PENDING_CAPACITY: '100',
      REGISTRATION_GLOBAL_DAILY_LIMIT: '100',
      REGISTRATION_EMAIL_HOURLY_LIMIT: '5',
      SMS_ENABLED: 'true',
      SMS_PROVIDER: 'smsir',
      SMS_IR_KEY_MODE: 'live',
      SMS_GATEWAY_API_KEY: apiKey,
      SMS_IR_TEMPLATE_ID: '1793984',
      SMS_IR_CODE_PARAMETER: 'OTP',
      SMS_OTP_HASH_PEPPER: randomBytes(32).toString('base64'),
      SMS_OTP_GLOBAL_PER_DAY: '100',
      SMS_OTP_MAX_PENDING_SIGNUP: '100',
      REGISTRATION_SMTP_HOST: 'smtp.registration.test',
      REGISTRATION_SMTP_PORT: '465',
      REGISTRATION_SMTP_TLS_MODE: 'implicit',
      REGISTRATION_SMTP_USERNAME: username,
      REGISTRATION_SMTP_PASSWORD: password,
      REGISTRATION_SMTP_FROM: controllerEnv.REGISTRATION_CONTROLLER_FROM,
      REGISTRATION_SMTP_PUBLIC_ORIGIN: origin,
      REGISTRATION_SMTP_CA_BUNDLE: '/certs/ca.pem',
      SSL_CERT_FILE: '/certs/ca.pem',
      HTTP_PROXY: '',
      HTTPS_PROXY: '',
      ALL_PROXY: '',
      NO_PROXY: '*',
    };
    for (const [name, value] of Object.entries(env))
      if (/(?:KEY|KEK|PEPPER|PASSWORD|USERNAME|_PEM|DATABASE_URL)$/.test(name)) remember(value);
    failureCheck = 'api-create';
    const api = createContainer(
      'api',
      [
        '--ip',
        gatewayTargets.apiHost,
        '--read-only',
        '--tmpfs',
        '/tmp:rw,noexec,nosuid,size=32m',
        '--cap-drop',
        'ALL',
        '--mount',
        `type=bind,source=${resolve(temporary, 'ca.pem')},target=/certs/ca.pem,readonly`,
      ],
      inputs.image,
      env
    );
    failureCheck = 'api-start';
    docker(['start', api.id], lifecycle);
    const [apiState] = JSON.parse(docker(['inspect', api.id], lifecycle));
    failureCheck = 'api-network';
    if (!apiState.State.Running) {
      const output = docker(['logs', '--tail', '20', api.id], lifecycle, { includeStderr: true });
      console.log(JSON.stringify({ check: 'registration-api-startup', ...registrationStartupSummary(output) }));
    }
    assertRegistrationAPINetwork(apiState, inputs.image, network.Id, gatewayTargets.apiHost);
    failureCheck = 'web-start';
    web = await startProductionWeb(nextPort, lifecycle);
    cleanup.push(web.close);
    for (const [selected, path] of [
      [apiPort, '/readyz'],
      [nextPort, '/register'],
    ]) {
      failureCheck = selected === apiPort ? 'api-ready' : 'web-ready';
      await waitUntil(async () => {
        web.healthy();
        const [state] = JSON.parse(docker(['inspect', api.id], lifecycle));
        fixed(state.State.Running, 'Production API exited');
        try {
          const response = await fetch(`http://127.0.0.1:${selected}${path}`, {
            signal: AbortSignal.timeout(1000),
            redirect: 'error',
            ...(selected === apiPort ? { headers: { host: new URL(origin).host } } : {}),
          });
          await response.arrayBuffer();
          return response.ok;
        } catch {
          return false;
        }
      }, lifecycle);
    }
    const inspect = (email) => {
      fixed(typeof email === 'string' && !email.includes("'"), 'Invalid owned mailbox inspection');
      return JSON.parse(
        sql(`SELECT json_build_object('accounts',(SELECT count(*) FROM public.users WHERE email='${email}'),
'ordinary',(SELECT count(*) FROM public.users WHERE email='${email}' AND status='active' AND password_hash IS NULL AND phone_encrypted IS NOT NULL AND octet_length(phone_encrypted)>0 AND length(phone_blind_index)=64 AND octet_length(webauthn_user_handle)=8 AND lifecycle_revision=1),
'credentials',(SELECT count(*) FROM public.webauthn_credentials w JOIN public.users u ON u.id=w.user_id WHERE u.email='${email}'),
'verified',(SELECT count(*) FROM public.webauthn_credentials w JOIN public.users u ON u.id=w.user_id WHERE u.email='${email}' AND w.user_verified AND w.user_present),
'roles',(SELECT count(*) FROM public.user_roles r JOIN public.users u ON u.id=r.user_id WHERE u.email='${email}'),
'created',(SELECT count(*) FROM public.event_outbox o JOIN public.users u ON u.id=o.lifecycle_user_id WHERE u.email='${email}' AND o.subject='identity.user.created'));`)
      );
    };
    const expire = (id) => {
      fixed(uuid.test(id), 'Invalid owned expiry reference');
      sql(`UPDATE public.registration_attempts SET created_at=created_at-interval '20 minutes',expires_at=expires_at-interval '20 minutes',
email_token_issued_at=email_token_issued_at-interval '20 minutes',email_token_expires_at=email_token_expires_at-interval '20 minutes',email_verified_at=email_verified_at-interval '20 minutes',
phone_verified_at=phone_verified_at-interval '20 minutes',passkey_created_at=passkey_created_at-interval '20 minutes',passkey_expires_at=passkey_expires_at-interval '20 minutes' WHERE id='${id}' AND state='pending';`);
    };
    return {
      manifest,
      identity,
      origin,
      tlsSPKI: tls.spki,
      control,
      inspect,
      expire,
      secrets,
      close,
      lifecycle,
      cleanupExpired: () =>
        packaged('cleanup-expired', 'registration-cleanup', ['once'], cleanupEnv),
      pendingExists: (id) => {
        fixed(uuid.test(id), 'Invalid owned attempt reference');
        return sql(`SELECT count(*) FROM public.registration_attempts WHERE id='${id}'`) !== '0';
      },
      sessionCount: () =>
        docker(
          [
            'exec',
            serviceStates[1].Id,
            'redis-cli',
            '--scan',
            '--pattern',
            'identity:session:v1:token:*',
          ],
          lifecycle
        )
          .trim()
          .split(/\r?\n/)
          .filter(Boolean).length,
      remember,
      assertPrivateLogs() {
        const outputs = [
          web.privateOutput(),
          ...containers.map((item) =>
            docker(['logs', item.id], lifecycle, { includeStderr: true })
          ),
        ];
        for (const output of outputs)
          for (const secret of secrets)
            fixed(!output.includes(secret), 'Private proof/provider data entered supervised logs');
      },
    };
  } catch (error) {
    const detail = registrationFailureDetails(error, failureCheck);
    throw await registrationStartupFailure(detail.failure_check, close, cleanupKnown);
  }
}

function observe(context, harness) {
  const state = {
    failures: new Set(),
    pending: [],
    starts: [],
    posts: [],
    replies: [],
    proofs: new Set(),
  };
  context.on('page', (page) => {
    page.on('pageerror', () => state.failures.add('browser-runtime'));
    page.on('console', (message) => {
      if (/hydration|Content Security Policy/i.test(message.text()))
        state.failures.add('browser-csp-hydration');
      for (const secret of harness.secrets)
        if (message.text().includes(secret)) state.failures.add('browser-private-console');
    });
    page.on('download', () => state.failures.add('unexpected-download'));
    page.on('request', (request) => {
      try {
        const url = new URL(request.url());
        fixed(
          (url.origin === harness.origin && !url.search && !url.hash) ||
            (url.origin === harness.origin && !url.pathname.startsWith('/api/')),
          'Unexpected browser request origin or authority URL'
        );
        if (!url.pathname.startsWith('/api/')) return;
        const headers = request.headers();
        fixed(!headers.referer, 'Browser leaked a referrer');
        fixed(headers.dpop, 'Missing browser DPoP');
        harness.remember(headers.dpop);
        const [header, claims] = headers.dpop
          .split('.')
          .slice(0, 2)
          .map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
        fixed(
          header.typ === 'dpop+jwt' &&
            header.alg === 'ES256' &&
            header.jwk?.crv === 'P-256' &&
            !header.jwk.d &&
            claims.htm === request.method() &&
            claims.htu === harness.origin + url.pathname &&
            !('ath' in claims),
          'Malformed outgoing public DPoP'
        );
        fixed(!state.proofs.has(claims.jti), 'Browser reused a DPoP proof');
        state.proofs.add(claims.jti);
        if (url.pathname.startsWith(root)) {
          fixed(
            !headers.cookie && !headers.authorization && !headers['x-portal-session'],
            'Signup transmitted session authority'
          );
          const body = request.postDataJSON();
          state.posts.push({ path: url.pathname, body });
          for (const key of ['capability', 'token', 'code', 'verification_id'])
            harness.remember(body[key]);
          for (const value of [
            body.credential?.id,
            body.credential?.rawId,
            body.credential?.response?.clientDataJSON,
            body.credential?.response?.attestationObject,
          ])
            harness.remember(value);
        }
      } catch {
        state.failures.add('browser-request-privacy');
      }
    });
    page.on('response', (response) => {
      if (!new URL(response.url()).pathname.startsWith('/api/')) return;
      const check = (async () => {
        const path = new URL(response.url()).pathname,
          headers = await response.allHeaders();
        fixed(
          /\bno-store\b/.test(headers['cache-control'] || '') &&
            headers['referrer-policy'] === 'no-referrer',
          'API response privacy policy mismatch'
        );
        if (path.startsWith(root)) {
          fixed(!headers['set-cookie'], 'Signup minted a session');
          let value;
          if (response.status() !== 204 && /json/.test(headers['content-type'] || ''))
            value = await response.json();
          state.replies.push({ path, status: response.status(), value, headers });
          if (path === root + '/start' && response.status() === 201) {
            fixed(
              uuid.test(value.attempt_id) && capability.test(value.capability),
              'Malformed signup authority'
            );
            state.starts.push(value);
            harness.remember(value.capability);
            harness.remember(value.canonical_email);
          }
          if (path === root + '/phone/send' && response.status() === 200)
            harness.remember(value.verification_id);
        } else if (headers['set-cookie']) {
          harness.remember(headers['set-cookie']);
          harness.remember(headers['set-cookie'].split(';')[0].split('=').slice(1).join('='));
        }
      })().catch(() => state.failures.add('browser-response-privacy'));
      state.pending.push(check);
    });
  });
  return state;
}

// Adversarial requests sign with real Web Crypto in the browser. They are test
// controllers for public endpoints, not exported application test APIs.
async function browserPost(page, path, body, foreign = false) {
  fixed(
    path === root || path.startsWith(root + '/') || path === '/api/v1/auth/profile',
    'Unexpected adversarial route'
  );
  return page.evaluate(
    async ({ path, body, foreign }) => {
      const b64 = (value) =>
        btoa(String.fromCharCode(...new Uint8Array(value)))
          .replace(/=/g, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
      let key;
      if (foreign) {
        const pair = await crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['sign', 'verify']
        );
        const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
        key = {
          privateKey: pair.privateKey,
          publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
        };
      } else
        key = await new Promise((yes, no) => {
          const open = indexedDB.open('hatef-portal-dpop', 1);
          open.onerror = () => no(new Error('Browser test key unavailable'));
          open.onsuccess = () => {
            const db = open.result,
              tx = db.transaction('keys'),
              request = tx.objectStore('keys').get('active');
            request.onsuccess = () => {
              db.close();
              yes(request.result);
            };
            request.onerror = () => {
              db.close();
              no(new Error('Browser test key unavailable'));
            };
          };
        });
      let nonce;
      for (let attempt = 0; attempt < 2; attempt++) {
        const header = b64(
          new TextEncoder().encode(
            JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk })
          )
        );
        const claims = b64(
          new TextEncoder().encode(
            JSON.stringify({
              htm: 'POST',
              htu: location.origin + path,
              iat: Math.floor(Date.now() / 1000),
              jti: crypto.randomUUID(),
              ...(nonce ? { nonce } : {}),
            })
          )
        );
        const data = header + '.' + claims;
        const signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          key.privateKey,
          new TextEncoder().encode(data)
        );
        const response = await fetch(path, {
          method: 'POST',
          credentials: 'omit',
          cache: 'no-store',
          referrerPolicy: 'no-referrer',
          headers: { 'content-type': 'application/json', DPoP: data + '.' + b64(signature) },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10000),
        });
        if (
          attempt === 0 &&
          response.status === 401 &&
          /use_dpop_nonce/.test(response.headers.get('www-authenticate') || '') &&
          response.headers.get('dpop-nonce')
        ) {
          nonce = response.headers.get('dpop-nonce');
          await response.arrayBuffer();
          continue;
        }
        const raw = await response.text();
        return {
          status: response.status,
          retryAfter: response.headers.get('retry-after'),
          value: raw ? JSON.parse(raw) : null,
        };
      }
      throw new Error('Browser nonce challenge was not resolved');
    },
    { path, body, foreign }
  );
}

async function assertNoStoredAuthority(page, harness) {
  const values = await page.evaluate(async () => {
    const result = [...Object.values(localStorage), ...Object.values(sessionStorage)];
    for (const info of await indexedDB.databases()) {
      await new Promise((yes, no) => {
        const open = indexedDB.open(info.name);
        open.onerror = () => no(new Error('Storage inspection failed'));
        open.onsuccess = () => {
          const db = open.result,
            names = [...db.objectStoreNames];
          if (!names.length) {
            db.close();
            yes();
            return;
          }
          const tx = db.transaction(names);
          for (const name of names) {
            const request = tx.objectStore(name).getAll();
            request.onsuccess = () => result.push(JSON.stringify(request.result));
          }
          tx.oncomplete = () => {
            db.close();
            yes();
          };
          tx.onerror = () => {
            db.close();
            no(new Error('Storage inspection failed'));
          };
        };
      });
    }
    return result;
  });
  for (const secret of harness.secrets)
    for (const value of values)
      fixed(!value.includes(secret), 'Signup authority entered persistent browser storage');
}
async function addAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}
async function document(page, harness, path = '/register') {
  await page.bringToFront();
  const response = await page.goto(harness.origin + path);
  fixed(response?.status() === 200, 'Production registration page failed');
}
async function newBrowserContext(browser, harness, options = {}) {
  const context = await browser.newContext({
    serviceWorkers: 'block',
    bypassCSP: false,
    ...options,
  });
  context.setDefaultTimeout(15000);
  context.setDefaultNavigationTimeout(30000);
  const observed = observe(context, harness),
    page = await context.newPage();
  await document(page, harness);
  return { context, page, observed };
}
const button = (page, label) => page.getByRole('button', { name: label, exact: true });
const registrationAlert = (page) => page.locator('[data-registration-feedback]').getByRole('alert');
async function startAttempt(page, observed, harness, suffix) {
  const raw = `  آزمايش${suffix}@BÜCHER.example  `,
    email = `آزمايش${suffix}@xn--bcher-kva.example`;
  const phone =
    '091' + String(parseInt(randomBytes(4).toString('hex'), 16) % 100000000).padStart(8, '0');
  harness.remember(raw);
  harness.remember(email);
  harness.remember(phone);
  const deliveryBefore = await harness.control('/summary');
  const count = observed.starts.length;
  await page.getByLabel('Email address', { exact: true }).fill(raw);
  await page.getByLabel('Iranian mobile number', { exact: true }).fill(phone);
  fixed(
    (await page.getByLabel('Email address', { exact: true }).getAttribute('type')) === 'text' &&
      (await page.getByLabel('Email address', { exact: true }).getAttribute('inputmode')) ===
        'email',
    'Native ASCII email validation returned'
  );
  await button(page, 'Start registration and send email').click();
  await waitUntil(async () => {
    await Promise.all(observed.pending);
    return observed.starts.length > count;
  }, harness.lifecycle);
  const authority = observed.starts.at(-1);
  fixed(
    authority.canonical_email === email && authority.email_sent === true,
    'Server canonical Unicode email/delivery contract failed'
  );
  fixed(
    observed.posts.some(
      (request) =>
        request.path === root + '/start' &&
        request.body.email === raw &&
        request.body.phone === phone
    ),
    'Frontend rewrote raw registration identifiers'
  );
  fixed(
    (await page.locator('bdi[dir="auto"]').innerText()) === email,
    'Canonical mailbox lacks bidi isolation'
  );
  await waitUntil(() => button(page, 'Check email verification').isEnabled(), harness.lifecycle);
  const delivered = await harness.control('/summary');
  fixed(
    delivered.mail === deliveryBefore.mail + 1 && delivered.sms === deliveryBefore.sms,
    'Start automatically sent SMS or repeated verification delivery'
  );
  const emailProof = await takeProof(harness, '/take-mail', { recipient: email });
  fixed((await harness.inspect(email)).accounts === 0, 'Start created an account before proofs');
  return { ...authority, email, emailProof, mobile: phone.slice(1), phone };
}
async function takeProof(harness, path, filter) {
  let value;
  await waitUntil(async () => {
    value = await harness.control(path, filter);
    return Boolean(value);
  }, harness.lifecycle);
  for (const key of ['token', 'code', 'link']) harness.remember(value[key]);
  return value;
}
async function verifyEmail(page, context, authority, harness, browser, mark, resend = false) {
  let proof = authority.emailProof;
  fixed(proof.attempt_id === authority.attempt_id, 'Mail proof crossed signup attempts');
  if (resend) {
    const old = proof;
    await button(page, 'Send another verification email').click();
    await page
      .getByRole('status')
      .filter({ hasText: 'A new email was accepted for delivery.' })
      .waitFor();
    proof = await takeProof(harness, '/take-mail', { recipient: authority.email });
    fixed(
      proof.attempt_id === old.attempt_id && proof.token !== old.token,
      'Email resend did not replace the separate proof'
    );
    const rejected = await browserPost(page, root + '/email/verify', {
      attempt_id: old.attempt_id,
      token: old.token,
    });
    fixed(rejected.status === 401, 'Resend left old email proof usable');
    const retained = await browserPost(page, root + '/result', {
      attempt_id: authority.attempt_id,
      capability: authority.capability,
    });
    fixed(
      retained.status === 200 &&
        retained.value.expires_at === authority.expires_at &&
        retained.value.email_verified === false,
      'Email resend extended or verified pending authority'
    );
    mark('email-resend-proof-invalidation');
  }
  const before = await harness.control('/summary');
  const foreign = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const wrongObserved = observe(foreign, harness);
    const wrong = await foreign.newPage();
    await wrong.goto(proof.link);
    await button(wrong, 'Verify email ownership').click();
    await registrationAlert(wrong).waitFor();
    fixed(new URL(wrong.url()).hash === '', 'Wrong-browser proof fragment remained');
    const initializedKey = await wrong.evaluate(async () => {
      if (!(await indexedDB.databases()).some((entry) => entry.name === 'hatef-portal-dpop'))
        return false;
      return new Promise((yes, no) => {
        const open = indexedDB.open('hatef-portal-dpop', 1);
        open.onerror = () => no(new Error('Key inspection failed'));
        open.onsuccess = () => {
          const db = open.result,
            request = db.transaction('keys').objectStore('keys').get('active');
          request.onsuccess = () => {
            db.close();
            yes(Boolean(request.result));
          };
          request.onerror = () => {
            db.close();
            no(new Error('Key inspection failed'));
          };
        };
      });
    });
    await Promise.all(wrongObserved.pending);
    fixed(
      !initializedKey && wrongObserved.posts.length === 0 && wrongObserved.failures.size === 0,
      'Wrong-browser email link initialized or sent authority'
    );
  } finally {
    await foreign.close();
  }
  mark('wrong-browser-link-denied');
  const same = await context.newPage();
  await same.goto(proof.link);
  await waitUntil(() => new URL(same.url()).hash === '', harness.lifecycle);
  const unverified = await browserPost(page, root + '/result', {
    attempt_id: authority.attempt_id,
    capability: authority.capability,
  });
  fixed(
    unverified.status === 200 && unverified.value.email_verified === false,
    'Opening a link automatically consumed email proof'
  );
  await same.bringToFront();
  await button(same, 'Verify email ownership').click();
  await same.getByRole('status').filter({ hasText: 'Email ownership is verified.' }).waitFor();
  fixed(new URL(same.url()).hash === '', 'Email proof fragment was not scrubbed');
  await same.close();
  await page.bringToFront();
  await button(page, 'Check email verification').click();
  await button(page, 'Send SMS code').waitFor();
  const replay = await browserPost(page, root + '/email/verify', {
    attempt_id: proof.attempt_id,
    token: proof.token,
  });
  fixed([400, 401, 409, 410].includes(replay.status), 'Email proof replay succeeded');
  const after = await harness.control('/summary');
  fixed(after.sms === before.sms, 'Email verification automatically sent an SMS');
  mark('explicit-smtputf8-email-proof');
  mark('proof-replay-denied');
}

async function exerciseSuccessfulSignup(
  browser,
  harness,
  mark,
  { mobile = false, dark = false, adversarial = false, rateResend = false, lost = false } = {}
) {
  const { context, page, observed } = await newBrowserContext(browser, harness, {
    viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 },
    colorScheme: dark ? 'dark' : 'light',
  });
  try {
    if (lost) {
      await page.evaluate(installCompletionDeadlineController);
      await page.route('**/api/v1/auth/register/start', async (route) => {
        const response = await route.fetch();
        if (response.status() === 201) {
          const start = await response.json();
          await page.evaluate(
            (expiry) => window.__registrationAcceptanceDeadline.observeStart(expiry),
            start.expires_at
          );
        }
        await route.fulfill({ response });
      });
    }
    const authenticator = await addAuthenticator(page);
    const sessionsBefore = harness.sessionCount();
    const authority = await startAttempt(page, observed, harness, randomBytes(6).toString('hex'));
    mark('unicode-canonical-mailbox');
    if (adversarial) {
      const missing = await browserPost(page, root + '/result', {
        attempt_id: authority.attempt_id,
      });
      fixed([400, 401].includes(missing.status), 'Missing signup capability was admitted');
      mark('missing-capability-denied');
      const foreign = await browserPost(
        page,
        root + '/result',
        { attempt_id: authority.attempt_id, capability: authority.capability },
        true
      );
      fixed(foreign.status === 401, 'Foreign browser key acquired signup authority');
      mark('foreign-jkt-denied');
    }
    await verifyEmail(page, context, authority, harness, browser, mark, adversarial);
    const beforeSMS = await harness.control('/summary');
    await button(page, 'Send SMS code').click();
    await page.getByLabel('SMS verification code', { exact: true }).waitFor();
    let sms = await takeProof(harness, '/take-sms', { mobile: authority.mobile });
    fixed(
      (await harness.control('/summary')).sms === beforeSMS.sms + 1,
      'SMS sender retried or delivered automatically'
    );
    mark('explicit-smsir-verify-contract');
    await Promise.all(observed.pending);
    const initialVerification = observed.replies.find(
      (reply) => reply.path === root + '/phone/send' && reply.status === 200
    )?.value?.verification_id;
    fixed(
      capability.test(initialVerification ?? ''),
      'SMS send did not return an exact verification reference'
    );
    harness.remember(initialVerification);
    if (adversarial) {
      // Correct the definitive wrong-code rejection on the same issued proof.
      // Resend/rate-limit behavior belongs to a separate owned attempt below.
      const wrong = '0' + String((Number(sms.code.slice(1)) + 1) % 100000).padStart(5, '0');
      fixed(wrong !== sms.code, 'Leading-zero negative vector unexpectedly matched');
      const wrongReply = page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === root + '/phone/verify' && response.status() === 409
      );
      await page.getByLabel('SMS verification code', { exact: true }).fill(wrong);
      await button(page, 'Verify phone').click();
      fixed(
        (await (await wrongReply).json()).error === 'proof_required',
        'Wrong OTP was not a definitive proof_required rejection'
      );
      await registrationAlert(page).waitFor();
      await waitUntil(
        () => page.getByLabel('SMS verification code', { exact: true }).isEnabled(),
        harness.lifecycle
      );
      fixed(
        observed.posts.some(
          (item) =>
            item.path === root + '/phone/verify' &&
            item.body.code === wrong &&
            item.body.verification_id === initialVerification
        ),
        'Frontend stripped a leading zero'
      );
      fixed(
        (await button(page, 'Send a new SMS code').isEnabled()) &&
          (await page.getByLabel('SMS verification code', { exact: true }).count()) === 1,
        'Definitive wrong OTP discarded its input/challenge'
      );
      fixed(
        (await harness.control('/summary')).sms === beforeSMS.sms + 1,
        'Wrong OTP automatically sent another SMS'
      );
      mark('leading-zero-otp-preserved');
    }
    if (rateResend) {
      await button(page, 'Send a new SMS code').click();
      await registrationAlert(page).waitFor();
      await waitUntil(async () => {
        await Promise.all(observed.pending);
        return observed.replies.some(
          (item) => item.path === root + '/phone/send' && item.status === 429
        );
      }, harness.lifecycle);
      fixed(
        observed.replies.some(
          (item) =>
            item.path === root + '/phone/send' &&
            item.status === 429 &&
            Number(item.headers['retry-after']) > 0
        ),
        'SMS rate limit lacked Retry-After'
      );
      fixed(
        (await page.getByLabel('SMS verification code', { exact: true }).count()) === 0,
        'Rate-limited resend retained an old verification input'
      );
      fixed(
        (await harness.control('/summary')).sms === beforeSMS.sms + 1,
        'Rate-limited request reached provider'
      );
      mark('rate-limit-retry-after');
      await delay(61000, undefined, { signal: harness.lifecycle.signal });
      await button(page, 'Send SMS code').click();
      await page.getByLabel('SMS verification code', { exact: true }).waitFor();
      sms = await takeProof(harness, '/take-sms', { mobile: authority.mobile });
      await Promise.all(observed.pending);
      const fresh = observed.replies
        .filter((reply) => reply.path === root + '/phone/send' && reply.status === 200)
        .at(-1)?.value?.verification_id;
      fixed(
        capability.test(fresh ?? '') && fresh !== initialVerification,
        'Explicit resend reused its discarded verification reference'
      );
      harness.remember(fresh);
    }
    const sentBeforeCorrection = (await harness.control('/summary')).sms;
    await page.getByLabel('SMS verification code', { exact: true }).fill(sms.code);
    await button(page, 'Verify phone').click();
    await button(page, 'Create passkey and complete registration').waitFor();
    if (adversarial) {
      await Promise.all(observed.pending);
      fixed(
        observed.replies.some(
          (reply) => reply.path === root + '/phone/verify' && reply.status === 204
        ),
        'Corrected OTP did not verify the same issued proof'
      );
      assertSamePhoneVerification(
        observed.posts,
        initialVerification,
        sms.code,
        sentBeforeCorrection,
        (await harness.control('/summary')).sms
      );
      fixed(
        (await harness.control('/summary')).sms === beforeSMS.sms + 1,
        'Corrected first-code retry billed another SMS'
      );
      mark('corrected-otp-same-reference');
    }
    const early = await harness.inspect(authority.email);
    fixed(
      early.accounts === 0 && early.credentials === 0 && early.roles === 0 && early.created === 0,
      'Ownership/options created account material early'
    );
    mark('ownership-before-account-birth');
    let optionsSeen = false;
    await page.route('**/api/v1/auth/register/passkey/options', async (route) => {
      const response = await route.fetch();
      if (response.status() === 200) {
        const options = (await response.json()).publicKey;
        fixed(
          options.user.name === authority.email &&
            options.user.displayName === authority.email &&
            Buffer.from(options.user.id, 'base64url').length === 8 &&
            options.authenticatorSelection.residentKey === 'required' &&
            options.authenticatorSelection.requireResidentKey === true &&
            options.authenticatorSelection.userVerification === 'required',
          'Production passkey options are not identity-bound resident UV'
        );
        const state = harness.inspect(authority.email);
        fixed(
          state.accounts === 0 && state.credentials === 0 && state.created === 0,
          'Options created account material'
        );
        optionsSeen = true;
      }
      await route.fulfill({ response });
    });
    if (adversarial) {
      await page.evaluate(() => {
        window.__registrationCreate = navigator.credentials.create;
        navigator.credentials.create = () =>
          Promise.reject(new DOMException('User canceled authenticator', 'NotAllowedError'));
      });
      await button(page, 'Create passkey and complete registration').click();
      await registrationAlert(page).waitFor();
      fixed(
        optionsSeen && harness.inspect(authority.email).accounts === 0,
        'Canceled passkey created an account'
      );
      await page.evaluate(() => {
        navigator.credentials.create = window.__registrationCreate;
        delete window.__registrationCreate;
      });
      mark('passkey-cancellation-no-birth');
    }
    let lostAccepted = false,
      finalBody,
      completionReceipt;
    await page.route('**/api/v1/auth/register', async (route) => {
      finalBody = route.request().postDataJSON();
      if (lost) await page.evaluate(() => window.__registrationAcceptanceDeadline.hold(true));
      const response = await route.fetch();
      if (response.status() === 200) completionReceipt = await response.json();
      if (lost && response.status() === 200) {
        lostAccepted = true;
        await waitUntil(
          async () => {
            const clock = await page.evaluate(() =>
              window.__registrationAcceptanceDeadline.snapshot()
            );
            return (
              clock.firedWhileHeld > 0 &&
              clock.uiRemaining < -1000 &&
              clock.clientMaximumRemaining < -1000
            );
          },
          harness.lifecycle,
          12000
        );
        const crossing = await page.evaluate(() =>
          window.__registrationAcceptanceDeadline.snapshot()
        );
        fixed(
          crossing.unchangedDate && crossing.unchangedRandom && crossing.held,
          'Completion crossing altered wall time/RNG or missed the actual in-flight request'
        );
        fixed(
          (await button(page, 'Check registration result').isDisabled()) &&
            (await button(page, 'Start a new registration').count()) === 0,
          'Pending timer discarded in-flight completion authority'
        );
        fixed(
          harness.inspect(authority.email).created === 1 &&
            harness.sessionCount() === sessionsBefore,
          'In-flight completion was not one committed birth without a session'
        );
        await response.dispose();
        await route.abort('failed');
      } else await route.fulfill({ response });
      if (lost) await page.evaluate(() => window.__registrationAcceptanceDeadline.hold(false));
    });
    if (lost) {
      const near = await page.evaluate(() => window.__registrationAcceptanceDeadline.arm());
      fixed(
        near.captured &&
          near.reads >= 2 &&
          near.uiRemaining >= 7000 &&
          near.uiRemaining <= 8500 &&
          near.clientMinimumRemaining >= 7000 &&
          near.clientMaximumRemaining <= 8500 &&
          near.unchangedDate &&
          near.unchangedRandom,
        'Client/UI original monotonic deadlines were not both near pending expiry'
      );
    }
    await button(page, 'Create passkey and complete registration').click();
    if (lost) {
      await button(page, 'Check registration result').waitFor();
      fixed(lostAccepted, 'Lost response was not a successful committed completion');
      const committed = await harness.inspect(authority.email);
      fixed(
        committed.accounts === 1 && committed.created === 1,
        'Lost completion did not commit once'
      );
      await button(page, 'Check registration result').click();
      mark('lost-completion-durable-receipt');
    }
    await page.getByRole('link', { name: 'Sign in with your passkey', exact: true }).waitFor();
    await page.unroute('**/api/v1/auth/register');
    await page.unroute('**/api/v1/auth/register/passkey/options');
    const created = await harness.inspect(authority.email);
    fixed(
      optionsSeen &&
        created.accounts === 1 &&
        created.ordinary === 1 &&
        created.credentials === 1 &&
        created.verified === 1 &&
        created.roles === 0 &&
        created.created === 1,
      'Signup birth was not one unprivileged atomic result'
    );
    fixed(
      (await context.cookies()).length === 0 && harness.sessionCount() === sessionsBefore,
      'Signup automatically created a session'
    );
    mark('atomic-unprivileged-account-birth');
    const credentials = await authenticator.cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authenticator.authenticatorId,
    });
    fixed(
      credentials.credentials.length === 1 &&
        credentials.credentials[0].isResidentCredential &&
        credentials.credentials[0].userHandle,
      'Browser passkey was not discoverable'
    );
    mark('resident-uv-passkey');
    const exact = await browserPost(page, root, finalBody);
    fixed(
      exact.status === 200 && exact.value.state === 'completed',
      'Identical completed receipt was not idempotent'
    );
    assert.deepEqual(
      exact.value,
      completionReceipt,
      'Completion replay extended or changed the original receipt'
    );
    if (lost) {
      await Promise.all(observed.pending);
      fixed(
        observed.replies.some(
          (reply) =>
            reply.path === root + '/result' &&
            JSON.stringify(reply.value) === JSON.stringify(completionReceipt)
        ),
        'Authorized recovery did not return the original completion receipt'
      );
      const crossing = await page.evaluate(() =>
        window.__registrationAcceptanceDeadline.snapshot()
      );
      fixed(
        crossing.firedWhileHeld > 0 &&
          crossing.uiRemaining < 0 &&
          crossing.clientMaximumRemaining < 0 &&
          crossing.unchangedDate &&
          crossing.unchangedRandom,
        'Explicit fresh-DPoP receipt lookup did not survive the original pending deadline'
      );
      mark('completion-pending-deadline-handoff');
    }
    const changedID = randomBytes(32).toString('base64url');
    const changed = await browserPost(page, root, {
      ...finalBody,
      credential: { ...finalBody.credential, id: changedID, rawId: changedID },
    });
    fixed(changed.status === 409, 'Changed completion replay did not conflict');
    fixed(
      (await harness.inspect(authority.email)).created === 1,
      'Completion replay created another account/event'
    );
    await assertNoStoredAuthority(page, harness);
    await page.getByRole('link', { name: 'Sign in with your passkey', exact: true }).click();
    await page.getByTestId('passkey-login').click();
    await page.waitForURL(harness.origin + '/dashboard');
    await page.getByTestId('portal-ready').waitFor();
    fixed(
      (await context.cookies()).some(
        (item) =>
          item.name === '__Host-session' &&
          item.httpOnly &&
          item.secure &&
          item.sameSite === 'Strict' &&
          item.path === '/'
      ),
      'Fresh passkey login did not establish a real secure session'
    );
    mark('fresh-discoverable-login');
    fixed(
      harness.sessionCount() === sessionsBefore + 1,
      'Normal discoverable login did not create exactly one fresh session'
    );
    await Promise.all(observed.pending);
    fixed(observed.failures.size === 0, 'Browser CSP, privacy or runtime assertion failed');
  } catch (error) {
    console.error(JSON.stringify({ check: 'registration-flow-failure', ...registrationBrowserDiagnostic(error, observed) }));
    throw error;
  } finally {
    try {
      if (lost && !page.isClosed())
        await page.evaluate(() => window.__registrationAcceptanceDeadline?.restore());
    } finally {
      await context.close();
    }
  }
}

async function exerciseBoundaries(browser, harness, mark) {
  for (const viewport of [
    { width: 1280, height: 900 },
    { width: 390, height: 844 },
  ])
    for (const colorScheme of ['light', 'dark']) {
      const { context, page, observed } = await newBrowserContext(browser, harness, {
        viewport,
        colorScheme,
      });
      try {
        await page.getByLabel('Email address', { exact: true }).fill('raw invalid <mailbox>');
        await button(page, 'Start registration and send email').click();
        fixed(
          await page
            .getByLabel('Email address', { exact: true })
            .evaluate((element) => document.activeElement === element),
          'Invalid input did not receive keyboard focus'
        );
        fixed(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          'Registration overflowed mobile/desktop width'
        );
        fixed(
          (await page.getByRole('status').count()) === 1 &&
            (await page.getByRole('status').getAttribute('aria-live')) === 'polite',
          'Registration status is not accessible'
        );
        await page.keyboard.press('Tab');
        fixed(
          await page.evaluate(
            () =>
              document.activeElement instanceof HTMLInputElement ||
              document.activeElement instanceof HTMLButtonElement
          ),
          'Keyboard focus was lost'
        );
        fixed(observed.starts.length === 0, 'Invalid raw input allocated signup state');
      } finally {
        await context.close();
      }
    }
  mark('desktop-mobile-light-dark');
  mark('keyboard-focus-status');
  const noJS = await browser.newContext({
    javaScriptEnabled: false,
    viewport: { width: 390, height: 844 },
    serviceWorkers: 'block',
  });
  try {
    const page = await noJS.newPage();
    let requests = 0;
    page.on('request', (request) => {
      if (new URL(request.url()).pathname.startsWith(root)) requests++;
    });
    await document(page, harness);
    fixed(
      await button(page, 'Start registration and send email').isDisabled(),
      'No-script signup is not inert'
    );
    fixed(await page.locator('noscript').innerText(), 'No-script safe explanation missing');
    fixed(requests === 0, 'No-script page transmitted proof');
  } finally {
    await noJS.close();
  }
  mark('noscript-inert');
  const unsupported = await browser.newContext({ serviceWorkers: 'block' });
  try {
    await unsupported.addInitScript(() =>
      Object.defineProperty(window, 'PublicKeyCredential', { value: undefined, configurable: true })
    );
    const page = await unsupported.newPage(),
      observed = observe(unsupported, harness);
    await document(page, harness);
    await page
      .getByLabel('Email address', { exact: true })
      .fill(`unsupported${randomBytes(6).toString('hex')}@example.test`);
    await page.getByLabel('Iranian mobile number', { exact: true }).fill('09123456789');
    await button(page, 'Start registration and send email').click();
    await registrationAlert(page).waitFor();
    fixed(observed.starts.length === 0, 'Unsupported passkey allocated an attempt');
  } finally {
    await unsupported.close();
  }
  mark('unsupported-passkey-inert');
  const { context, page, observed } = await newBrowserContext(browser, harness);
  try {
    await addAuthenticator(page);
    const authority = await startAttempt(page, observed, harness, randomBytes(6).toString('hex'));
    await button(page, 'Cancel registration').click();
    await button(page, 'Start a new registration').waitFor();
    fixed(
      (await page.locator('bdi').count()) === 0 &&
        (await harness.inspect(authority.email)).accounts === 0,
      'Cancel retained visible authority or created an account'
    );
    await assertNoStoredAuthority(page, harness);
    mark('cancel-clears-authority');
    await button(page, 'Start a new registration').click();
    const expired = await startAttempt(page, observed, harness, randomBytes(6).toString('hex'));
    harness.expire(expired.attempt_id);
    const denied = await browserPost(page, root + '/result', {
      attempt_id: expired.attempt_id,
      capability: expired.capability,
    });
    fixed(
      denied.status === 410 && (await harness.inspect(expired.email)).accounts === 0,
      'Expired authority was usable'
    );
    mark('expired-authority-denied');
    harness.cleanupExpired();
    fixed(
      !harness.pendingExists(expired.attempt_id),
      'Packaged cleanup retained expired unheld pending state'
    );
    await button(page, 'Cancel registration').click();
    await button(page, 'Start a new registration').click();
    const rotated = await startAttempt(page, observed, harness, randomBytes(6).toString('hex'));
    const tab = await context.newPage();
    await document(tab, harness, '/login');
    await tab.evaluate(async () => {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ]);
      const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
      await new Promise((yes, no) => {
        const open = indexedDB.open('hatef-portal-dpop', 1);
        open.onerror = no;
        open.onsuccess = () => {
          const db = open.result,
            tx = db.transaction('keys', 'readwrite');
          tx.objectStore('keys').put(
            {
              privateKey: pair.privateKey,
              publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
            },
            'active'
          );
          tx.oncomplete = () => {
            db.close();
            yes();
          };
          tx.onerror = no;
        };
      });
    });
    await page.bringToFront();
    await button(page, 'Start a new registration').waitFor();
    fixed(
      (await harness.inspect(rotated.email)).accounts === 0,
      'Cross-tab key change created an account'
    );
    await tab.close();
    mark('cross-tab-key-change-clears');
    await assertNoStoredAuthority(page, harness);
  } finally {
    await context.close();
  }
}

export async function runRegistrationBrowser() {
  const lifecycle = acceptanceLifecycle(),
    checks = new Set();
  let harness,
    browser,
    inputs,
    identity,
    cleanup = { completed: false },
    failed = true,
    failureCheck = 'inputs',
    failure;
  const mark = (check) => {
    lifecycle.check();
    fixed(registrationChecks.includes(check), 'Unknown executed registration check');
    checks.add(check);
  };
  const interrupted = () => {
    void browser?.close().catch(() => {});
    void harness?.close().catch(() => {});
  };
  lifecycle.signal.addEventListener('abort', interrupted, { once: true });
  try {
    inputs = runtimeInputs();
    failureCheck = 'output-collision';
    try {
      await access(resolve(inputs.directory, 'registration-evidence.json'));
      throw new Error('Registration evidence output collision');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    failureCheck = 'identity';
    identity = await acceptanceIdentity();
    lifecycle.check();
    failureCheck = 'manifest-read';
    harness = await startRegistrationHarness(inputs, lifecycle, identity);
    mark('immutable-quality-image');
    mark('isolated-production-services');
    mark('packaged-migration-cleanup');
    failureCheck = 'browser';
    const { chromium } = await import('playwright');
    browser = await chromium.launch({
      headless: true,
      timeout: Math.min(60000, lifecycle.remaining()),
      args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`],
    });
    failureCheck = 'flow-desktop-light';
    await exerciseSuccessfulSignup(browser, harness, mark, { adversarial: true });
    failureCheck = 'flow-desktop-dark';
    await exerciseSuccessfulSignup(browser, harness, mark, { dark: true, rateResend: true });
    failureCheck = 'flow-mobile-light';
    await exerciseSuccessfulSignup(browser, harness, mark, { mobile: true });
    failureCheck = 'flow-mobile-dark';
    await exerciseSuccessfulSignup(browser, harness, mark, {
      mobile: true,
      dark: true,
      lost: true,
    });
    failureCheck = 'boundaries';
    await exerciseBoundaries(browser, harness, mark);
    failureCheck = 'provider-counts';
    const controller = await harness.control('/summary');
    fixed(
      controller.violations === 0 &&
        controller.auth > 0 &&
        controller.sms === 5 &&
        controller.mail === 8,
      'Provider/relay contract evidence failed'
    );
    failureCheck = 'private-logs';
    harness.assertPrivateLogs();
    mark('proof-storage-console-network-private');
    failureCheck = 'teardown';
    lifecycle.beginTeardown();
    await boundedTeardown(() => browser.close(), lifecycle);
    browser = undefined;
    cleanup = await harness.close();
    lifecycle.check(true);
    lifecycle.signal.throwIfAborted();
    // Teardown evidence is only added after all actual owned disposers succeed.
    checks.add('verified-owned-teardown');
    assertFullEvidence([...checks]);
    failureCheck = 'final-identity';
    assertIdentity(await boundedTeardown(() => acceptanceIdentity(), lifecycle), identity);
    lifecycle.check(true);
    const report = {
      schema: 1,
      kind: 'registration-browser',
      scope: 'full',
      status: 'passed',
      identity,
      apiImageId: inputs.image,
      cleanup,
      exit: 0,
      failed: 0,
      skipped: 0,
      tests: checks.size,
      checks: [...checks].sort(),
    };
    failureCheck = 'evidence';
    assertRegistrationReport(report, harness.manifest);
    await mkdir(inputs.directory, { recursive: true });
    await writeFile(
      resolve(inputs.directory, 'registration-evidence.json'),
      JSON.stringify(report) + '\n',
      { mode: 0o600, flag: 'wx' }
    );
    failed = false;
    return report;
  } catch (error) {
    if (harness) console.error(JSON.stringify({ check: 'registration-browser-failure', ...registrationBrowserDiagnostic(error) }));
    failure = registrationFailureDetails(error, failureCheck);
    if (!harness) cleanup = failure.cleanup;
  } finally {
    lifecycle.beginTeardown();
    let teardownFailed = false;
    try {
      if (browser) await boundedTeardown(() => browser.close(), lifecycle);
    } catch {
      teardownFailed = true;
    }
    try {
      if (harness) cleanup = await harness.close();
    } catch {
      teardownFailed = true;
    }
    lifecycle.signal.removeEventListener('abort', interrupted);
    lifecycle.release();
    if (failed && inputs && identity) {
      const detail = failure ?? registrationFailureDetails(undefined, failureCheck);
      const report = {
        schema: 1,
        kind: 'registration-browser',
        scope: 'full',
        status: 'failed',
        failure_stage: detail.failure_stage,
        failure_check: detail.failure_check,
        identity,
        apiImageId: inputs.image,
        cleanup: { completed: !teardownFailed && cleanup.completed === true },
        exit: 1,
        failed: 1,
        skipped: 0,
        tests: checks.size,
        checks: [...checks].sort(),
      };
      try {
        await mkdir(inputs.directory, { recursive: true });
        await writeFile(
          resolve(inputs.directory, 'registration-evidence.json'),
          JSON.stringify(report) + '\n',
          { mode: 0o600, flag: 'wx' }
        );
      } catch {
        throw new RegistrationFailure('evidence', !teardownFailed && cleanup.completed === true);
      }
    }
    if (failed)
      throw new RegistrationFailure(
        failure?.failure_check ?? failureCheck,
        !teardownFailed && cleanup.completed === true
      );
    if (teardownFailed) throw new RegistrationFailure('teardown', false);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length === 3 && process.argv[2] === '--controller') {
      fixed(
        /^[a-f0-9]{32}$/.test(process.env.REGISTRATION_CONTROLLER_RUN_ID || ''),
        'Controller requires run-owned admission'
      );
      const controller = await startRegistrationController({
        key: await readFile('/certs/key.pem'),
        cert: await readFile('/certs/cert.pem'),
        token: process.env.REGISTRATION_CONTROLLER_TOKEN,
        apiKey: process.env.REGISTRATION_CONTROLLER_API_KEY,
        username: process.env.REGISTRATION_CONTROLLER_USERNAME,
        password: process.env.REGISTRATION_CONTROLLER_PASSWORD,
        from: process.env.REGISTRATION_CONTROLLER_FROM,
        origin: process.env.REGISTRATION_CONTROLLER_ORIGIN,
        templateId: 1793984,
        parameter: 'OTP',
        ...(process.env.REGISTRATION_CONTROLLER_GATEWAY
          ? { gateway: JSON.parse(process.env.REGISTRATION_CONTROLLER_GATEWAY) }
          : {}),
      });
      let closing;
      const stop = () => {
        closing ||= controller.close().then(
          () => {
            process.exitCode = 0;
          },
          () => {
            process.exitCode = 1;
          }
        );
      };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    } else {
      fixed(process.argv.length === 2, 'Unknown registration browser option');
      await runRegistrationBrowser();
      console.log('Registration browser acceptance passed with verified cleanup.');
    }
  } catch (error) {
    const fallback = process.argv[2] === '--controller' ? 'controller-mode' : 'inputs';
    const detail = registrationFailureDetails(error, fallback);
    console.log(
      `Registration failure stage=${detail.failure_stage} check=${detail.failure_check} cleanup=${detail.cleanup.completed ? 'completed' : 'incomplete'}.`
    );
    console.error(registrationFailureMessage(error, fallback));
    process.exitCode = 1;
  }
}
