import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { access, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { createServer as tcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { startMailSink } from './portal-mail-sink.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const backend = resolve(workspace, 'apps/identity-api');

export function portalRoute(path) {
  return path
    .replace(/(\/auth\/webauthn\/keys\/)[^/]+$/, '$1{id}')
    .replace(/(\/users\/me\/sessions\/)[^/]+$/, '$1{id}');
}

export function replicaFor(path, sequence) {
  // Explicitly cross processes for portal and anonymous recovery ceremonies, including
  // nonce retries. Round-robin alone could put every successful retry on B.
  if (path === '/api/v1/auth/deletion/reclaim/options') return 0;
  if (path === '/api/v1/auth/deletion/reclaim' || path === '/api/v1/auth/deletion/reclaim/') return 1;
  if (path.endsWith('/generate-options') || path.endsWith('/stepup/challenge')) return 0;
  if (path.endsWith('/verify')) return 1;
  return sequence % 2;
}

export function anonymousReclaim(path, method) {
  return method === 'POST' && [
    '/api/v1/auth/deletion/reclaim/options',
    '/api/v1/auth/deletion/reclaim',
    '/api/v1/auth/deletion/reclaim/',
  ].includes(path);
}

export function secretEnvironmentValues(environment) {
  return Object.entries(environment)
    .filter(
      ([key, value]) => /KEY|KEK|SECRET|PEPPER|PASSWORD|TOKEN/.test(key) && typeof value === 'string' && value.length >= 32
    )
    .map(([, value]) => value);
}

export function fixtureSecretValues(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, item]) => {
    if (key === 'database_url' && typeof item === 'string') {
      try {
        return [item, decodeURIComponent(new URL(item).password)].filter(Boolean);
      } catch {
        return [item];
      }
    }
    if (/^(?:code|secret|totp_secret|otpauth_url|privateKey|key|user_id|email|backup_email|recipient|token|reclaim_token|link|recovery_url|database_url|password)$/i.test(key)) {
      return typeof item === 'string' && item ? [item] : [];
    }
    if (key === 'codes' && Array.isArray(item)) {
      return item.filter((code) => typeof code === 'string' && code);
    }
    return fixtureSecretValues(item);
  });
}

export function redactFixtureSecrets(text, secrets) {
  const values = [...new Set(secrets)]
    .filter((value) => typeof value === 'string' && value)
    .sort((a, b) => b.length - a.length);
  for (const value of values) {
    text = text.replaceAll(value, '[fixture redacted]');
    text = text.replaceAll(JSON.stringify(value).slice(1, -1), '[fixture redacted]');
  }
  return text;
}

export function browserFailure(error, stage = 'unknown') {
  const kind = error?.name === 'AssertionError' ? 'assertion' : 'operation';
  const location = typeof error?.stack === 'string'
    ? error.stack.match(/web-portal\.browser\.mjs:\d+:\d+/)?.[0]
    : undefined;
  const checkpoint = /^[a-z-]{1,64}$/.test(stage) ? stage : 'unknown';
  // Browser exception messages can embed full Cookie/DPoP/grant headers or DOM
  // values. Source coordinates and a fixed checkpoint are enough to investigate.
  return `Portal browser ${kind} failed during ${checkpoint}${location ? ` at ${location}` : ''}; sensitive exception details suppressed.`;
}

export function assertLocalOrigin(value) {
  const origin = new URL(value);
  assert.equal(origin.protocol, 'https:', 'Portal browser tests require HTTPS');
  assert.equal(origin.hostname, 'localhost', 'Portal tests must not target a deployed service');
  assert(origin.port && origin.origin === value, 'Expected an exact ephemeral localhost origin');
  return origin;
}

function docker(args, allowFailure = false) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  if (result.error || (!allowFailure && result.status !== 0)) {
    throw new Error(`Disposable Docker ${args[0]} failed: ${result.error?.code || result.stderr}`);
  }
  return result;
}

async function waitFor(check, description, timeout = 60_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await check()) return;
    await delay(200);
  }
  throw new Error(`Timed out waiting for ${description}`);
}

async function freePort() {
  const server = tcpServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function cleanEnvironment() {
  // Do not inherit a developer's DATABASE_URL, signing keys, admin/gRPC flags,
  // proxy settings, peppers, or credential state into acceptance fixtures.
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      /^(?:path|systemroot|windir|comspec|pathext|temp|tmp|home|userprofile|lang|lc_all)$/i.test(
        key
      )
    )
  );
}

export async function startPortalHarness() {
  let apiBinary = resolve(backend, 'bin/identity-api');
  let fixtureBinary = resolve(backend, 'bin/portal-fixture');
  let notifierBinary = resolve(backend, 'bin/deletion-notifier');
  await Promise.all([
    access(apiBinary),
    access(fixtureBinary),
    access(notifierBinary),
    access(resolve(workspace, 'apps/web/.next/BUILD_ID')),
  ]).catch(() => {
    throw new Error(
      'Build web, identity-api, identity-api:build-portal-fixture, and identity-api:build-deletion-notifier before this suite'
    );
  });

  const runID = randomBytes(16).toString('hex');
  const name = `portal-browser-${runID}`;
  const database = `portal_browser_${runID}`;
  const password = randomBytes(24).toString('hex');
  const cleanup = [];
  const children = [];
  const responseCounts = new Map();
  const secrets = [password];
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    for (const dispose of cleanup.reverse()) {
      try {
        await dispose();
      } catch {
        console.error('A disposable portal resource did not cleanly stop');
      }
    }
  };
  const diagnostics = () => {
    console.error('Public API response counts:', redactFixtureSecrets(JSON.stringify(Object.fromEntries(responseCounts)), secrets));
    for (const { label, output } of children) {
      const redacted = redactFixtureSecrets(output.join(''), secrets).slice(label === 'Deletion notifier' ? -4096 : -16_384);
      // No browser traces, request dumps, fixture stdout, or recovery batches.
      console.error(`${label} process diagnostics:\n${redacted}`);
    }
  };
  const start = (label, command, args, env, cwd = workspace) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...cleanEnvironment(), ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const output = [];
    const record = (chunk) => {
      output.push(String(chunk));
      while (output.join('').length > 65_536) output.shift();
    };
    child.stdout.on('data', record);
    child.stderr.on('data', record);
    child.on('error', (error) => record(`process error: ${error.code}`));
    children.push({ label, child, output });
    cleanup.push(async () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const exit = once(child, 'exit').catch(() => {});
      child.kill('SIGTERM');
      await Promise.race([exit, delay(10_000, undefined, { ref: false })]);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await exit;
      }
    });
    return child;
  };

  try {
    if (process.platform === 'win32') {
      // Existing Nx Go targets intentionally use extensionless Linux artifact
      // names. Windows CreateProcess needs .exe; do not rename shared build output.
      const parent = resolve(tmpdir(), 'kilo');
      await mkdir(parent, { recursive: true });
      const temporary = await mkdtemp(resolve(parent, 'portal-browser-binaries-'));
      cleanup.push(() => rm(temporary, { recursive: true, force: true }));
      const apiExecutable = resolve(temporary, 'identity-api.exe');
      const fixtureExecutable = resolve(temporary, 'portal-fixture.exe');
      const notifierExecutable = resolve(temporary, 'deletion-notifier.exe');
      await Promise.all([copyFile(apiBinary, apiExecutable), copyFile(fixtureBinary, fixtureExecutable), copyFile(notifierBinary, notifierExecutable)]);
      apiBinary = apiExecutable;
      fixtureBinary = fixtureExecutable;
      notifierBinary = notifierExecutable;
    }
    docker(['network', 'create', '--label', 'ldp.task=7.3', name]);
    cleanup.push(() => docker(['network', 'rm', name], true));
    const container = (suffix, ports, image, args = [], environment = {}) => {
      const id = `${name}-${suffix}`;
      cleanup.push(() => docker(['rm', '--force', '--volumes', id], true));
      docker([
        'run',
        '--detach',
        '--name',
        id,
        '--network',
        name,
        '--label',
        'ldp.task=7.3',
        ...ports.flatMap((port) => ['--publish', `127.0.0.1::${port}`]),
        ...Object.entries(environment).flatMap(([key, value]) => ['--env', `${key}=${value}`]),
        image,
        ...args,
      ]);
      const [state] = JSON.parse(docker(['inspect', id]).stdout);
      const exposed = Object.fromEntries(
        ports.map((port) => {
          const [binding] = state.NetworkSettings.Ports[`${port}/tcp`];
          assert.equal(binding.HostIp, '127.0.0.1');
          return [port, Number(binding.HostPort)];
        })
      );
      return { id, ports: exposed };
    };
    const postgres = container('postgres', [5432], 'postgres:16-alpine', [], {
      POSTGRES_USER: 'portal',
      POSTGRES_PASSWORD: password,
      POSTGRES_DB: database,
    });
    const redis = container('redis', [6379], 'redis:7-alpine', [
      'redis-server',
      '--save',
      '',
      '--appendonly',
      'no',
      '--maxmemory',
      '96mb',
      '--maxmemory-policy',
      'noeviction',
    ]);
    const nats = container('nats', [4222, 8222], 'nats:2.10-alpine', [
      '-js',
      '-sd',
      '/data',
      '-m',
      '8222',
    ]);
    await waitFor(
      () =>
        docker(
          ['exec', postgres.id, 'pg_isready', '-h', '127.0.0.1', '-U', 'portal', '-d', database],
          true
        ).status === 0,
      'disposable PostgreSQL'
    );
    await waitFor(
      () => docker(['exec', redis.id, 'redis-cli', 'ping'], true).stdout.trim() === 'PONG',
      'disposable Redis'
    );
    await waitFor(async () => {
      try {
        const response = await fetch(
          `http://127.0.0.1:${nats.ports[8222]}/healthz?js-enabled-only=true`,
          {
            signal: AbortSignal.timeout(1000),
            redirect: 'error',
          }
        );
        return response.ok;
      } catch {
        return false;
      }
    }, 'disposable JetStream');

    const storeEnv = {
      DATABASE_URL: `postgres://portal:${password}@127.0.0.1:${postgres.ports[5432]}/${database}?sslmode=disable`,
      REDIS_URL: `redis://127.0.0.1:${redis.ports[6379]}/0`,
      NATS_URL: `nats://127.0.0.1:${nats.ports[4222]}`,
      AUDIT_STREAM_NAME: `PORTAL_BROWSER_AUDIT_${runID}`,
      ENVELOPE_MASTER_KEK: randomBytes(32).toString('base64'),
      ENVELOPE_MASTER_KEK_VERSION: '1',
    };
    secrets.push(...secretEnvironmentValues(storeEnv));
    const fixture = (action, input = {}) => {
      secrets.push(...fixtureSecretValues(input));
      const result = spawnSync(fixtureBinary, [action], {
        cwd: backend,
        env: {
          ...cleanEnvironment(),
          ...storeEnv,
          APP_ENV: 'test',
          PORTAL_FIXTURE_ALLOW: '1',
          PORTAL_FIXTURE_RUN_ID: runID,
        },
        input: JSON.stringify(input),
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 128 * 1024,
        windowsHide: true,
      });
      assert(!result.error && result.status === 0,
        `Test-only fixture ${action} failed: ${result.error?.code || `exit ${result.status}`}`);
      let value;
      try {
        value = JSON.parse(result.stdout);
      } catch {
        throw new Error(`Test-only fixture ${action} did not return bounded JSON`);
      }
      secrets.push(...fixtureSecretValues(value));
      return value;
    };
    const waitForNoticeCleanup = async (userID, accepted) => {
      let state;
      await waitFor(() => {
        state = fixture('deletion-state', { user_id: userID });
        return state.accepted === accepted && state.payloads === 0;
      }, 'relay acceptance bookkeeping and ciphertext cleanup', 15_000);
      return state;
    };
    fixture('migrate');
    const tls = fixture('tls');
    secrets.push(tls.key);
    const tlsSPKI = createHash('sha256')
      .update(new X509Certificate(tls.cert).publicKey.export({ type: 'spki', format: 'der' }))
      .digest('base64');
    const apiPorts = [await freePort(), await freePort()];
    const nextPort = await freePort();
    let sequence = 0;
    const routeEvidence = new Map();
    const originEvidence = { unsafe: 0, anonymous: 0, mismatched: 0, referrers: 0 };
    const captures = new Map();
    // Observe the real upstream body before Chromium discards a completed,
    // cancelled fetch. Nothing is replayed, changed, or written to an artifact.
    const captureJSON = (path, method, status) => {
      const key = `${method} ${path}`;
      assert([
        'POST /api/v1/auth/recovery-codes/generate',
        'POST /api/v1/auth/webauthn/register/verify',
        'POST /api/v1/auth/stepup/verify',
        'POST /api/v1/auth/deletion/reclaim/options',
        'POST /api/v1/auth/deletion/reclaim/',
      ].includes(key), 'Unsupported response capture');
      assert(!captures.has(key), 'Response capture already armed');
      let timer;
      let finish;
      let settled = false;
      const promise = new Promise((resolve, reject) => {
        finish = (error, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          captures.delete(key);
          if (error) reject(new Error('Bounded upstream response capture failed'));
          else resolve(value);
        };
      });
      void promise.catch(() => {});
      timer = setTimeout(() => finish(true), 20_000);
      timer.unref();
      captures.set(key, { status, finish });
      return promise;
    };
    cleanup.push(() => {
      for (const capture of captures.values()) capture.finish(true);
    });
    let origin;
    const ingress = httpsServer({ ...tls, minVersion: 'TLSv1.2' }, (request, response) => {
      if (!origin || request.headers.host !== new URL(origin).host) {
        response.writeHead(421).end();
        return;
      }
      const path = new URL(request.url, origin).pathname;
      const api = path === '/api' || path.startsWith('/api/');
      if (api && (request.headers.dpop || anonymousReclaim(path, request.method)) && !['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        originEvidence.unsafe++;
        if (anonymousReclaim(path, request.method)) originEvidence.anonymous++;
        if (request.headers.origin !== origin) originEvidence.mismatched++;
        if (request.headers.referer) originEvidence.referrers++;
      }
      const replica = replicaFor(path, sequence++);
      const upstream = httpRequest(
        {
          hostname: '127.0.0.1',
          port: api ? apiPorts[replica] : nextPort,
          method: request.method,
          path: request.url,
          headers: {
            ...request.headers,
            host: new URL(origin).host,
            'x-forwarded-for': request.socket.remoteAddress,
            'x-forwarded-proto': 'https',
            'x-forwarded-host': new URL(origin).host,
          },
          timeout: 15_000,
        },
        (result) => {
          if (api) {
            const summary = `${request.method} ${portalRoute(path)} ${result.statusCode}`;
            responseCounts.set(summary, (responseCounts.get(summary) || 0) + 1);
          }
          const key = `${request.method} ${path}`;
          const capture = captures.get(key);
          if (capture && result.statusCode === capture.status) {
            const chunks = [];
            let size = 0;
            let failed = false;
            result.on('data', (chunk) => {
              size += chunk.length;
              if (size > 256 * 1024) failed = true;
              if (!failed) chunks.push(chunk);
            });
            result.once('error', () => capture.finish(true));
            result.once('aborted', () => capture.finish(true));
            result.once('end', () => {
              try {
                assert(!failed && /^application\/json\b/i.test(result.headers['content-type'] || ''));
                capture.finish(false, JSON.parse(Buffer.concat(chunks).toString('utf8')));
              } catch {
                capture.finish(true);
              } finally {
                chunks.length = 0;
              }
            });
          }
          if (api && result.statusCode >= 200 && result.statusCode < 300) {
            const key = `${request.method} ${portalRoute(path)}`;
            const hits = routeEvidence.get(key) || [0, 0];
            hits[replica]++;
            routeEvidence.set(key, hits);
          }
          response.writeHead(result.statusCode, result.headers);
          result.pipe(response);
        }
      );
      upstream.on('timeout', () => upstream.destroy());
      upstream.on('error', () => {
        if (!response.headersSent)
          response.writeHead(502, { 'Cache-Control': 'private, no-store' });
        response.end();
      });
      request.on('aborted', () => upstream.destroy());
      request.pipe(upstream);
    });
    ingress.listen(0, '127.0.0.1');
    await once(ingress, 'listening');
    cleanup.push(
      () =>
        new Promise((resolve) => {
          ingress.close(resolve);
          ingress.closeAllConnections();
        })
    );
    origin = `https://localhost:${ingress.address().port}`;
    assertLocalOrigin(origin);
    const mailParent = resolve(tmpdir(), 'kilo');
    await mkdir(mailParent, { recursive: true });
    const temporary = await mkdtemp(resolve(mailParent, 'portal-browser-mail-'));
    cleanup.push(() => rm(temporary, { recursive: true, force: true }));
    const caBundle = resolve(temporary, 'ca.pem');
    // Only the ephemeral public CA is written. Mail, bearer tokens, credentials,
    // private TLS keys, and browser traces never become filesystem artifacts.
    await writeFile(caBundle, tls.ca, { mode: 0o600 });
    const smtpUsername = randomBytes(24).toString('hex');
    const smtpPassword = randomBytes(32).toString('hex');
    const smtpFrom = `notices@${runID}.example.test`;
    secrets.push(smtpUsername, smtpPassword);
    const mail = await startMailSink({
      ...tls, username: smtpUsername, password: smtpPassword, from: smtpFrom,
      runID, origin, onSecrets: (values) => secrets.push(...values),
    });
    cleanup.push(() => mail.close());
    const workerDatabase = fixture('notifier-role');
    const notifierEnvironment = {
      ...storeEnv,
      DATABASE_URL: '',
      APP_ENV: 'production',
      DELETION_NOTIFIER_DATABASE_URL: workerDatabase.database_url,
      DELETION_SMTP_HOST: '127.0.0.1',
      DELETION_SMTP_PORT: String(mail.port),
      DELETION_SMTP_TLS_MODE: 'implicit',
      DELETION_SMTP_USERNAME: smtpUsername,
      DELETION_SMTP_PASSWORD: smtpPassword,
      DELETION_SMTP_FROM: smtpFrom,
      DELETION_SMTP_PUBLIC_ORIGIN: origin,
      DELETION_SMTP_CA_BUNDLE: caBundle,
      DELETION_SMTP_TIMEOUT: '2s',
      DELETION_NOTIFIER_POLL_INTERVAL: '1s',
      DELETION_NOTIFIER_RETRY_BASE: '1s',
      DELETION_NOTIFIER_RETRY_MAX: '2s',
      GDPR_GRACE_PERIOD: '720h',
    };
    secrets.push(...secretEnvironmentValues(notifierEnvironment));
    let notifier;
    const startNotifier = () => {
      assert(!notifier || notifier.exitCode !== null || notifier.signalCode !== null,
        'A notifier process is already running');
      notifier = start('Deletion notifier', notifierBinary, ['run'], notifierEnvironment, backend);
    };
    const stopNotifier = async () => {
      if (!notifier || notifier.exitCode !== null || notifier.signalCode !== null) return;
      const exited = once(notifier, 'exit');
      notifier.kill('SIGTERM');
      await Promise.race([exited, delay(10_000, undefined, { ref: false }).then(() => { throw new Error('Notifier did not stop'); })]);
    };
    const signingKey = () =>
      generateKeyPairSync('ec', { namedCurve: 'P-256' })
        .privateKey.export({ type: 'pkcs8', format: 'pem' })
        .toString();
    const apiEnvironment = {
      ...storeEnv,
      APP_ENV: 'production',
      HOST: '127.0.0.1',
      PORTAL_ORIGIN: origin,
      OIDC_ISSUER: origin,
      OIDC_SIGNING_KEY_ACTIVE_PEM: signingKey(),
      OIDC_SIGNING_KEY_NEXT_PEM: signingKey(),
      OIDC_CLIENTS_JSON: JSON.stringify([
        {
          client_id: 'portal-browser-fixture',
          redirect_uris: [`${origin}/callback`],
          token_endpoint_auth_method: 'none',
          allowed_scopes: ['openid', 'profile'],
        },
      ]),
      WEBAUTHN_RP_ID: 'localhost',
      WEBAUTHN_RP_ORIGINS: origin,
      WEBAUTHN_RP_DISPLAY_NAME: 'Portal Browser Test',
      WEBAUTHN_USER_VERIFICATION: 'required',
      WEBAUTHN_RESIDENT_KEY: 'required',
      WEBAUTHN_MOCK_CHALLENGE_KEY: randomBytes(32).toString('base64'),
      STEPUP_REPLAY_HMAC_KEY: randomBytes(32).toString('base64'),
      SMS_GATEWAY_API_KEY: randomBytes(32).toString('hex'),
      SESSION_COOKIE_NAME: '__Host-session',
      SESSION_COOKIE_SECURE: 'true',
      SESSION_ABSOLUTE_TTL: '2h',
      SESSION_IDLE_TTL: '30m',
      TRUSTED_PROXY_CIDRS: '127.0.0.1/32',
      ADMIN_ENABLED: 'false',
      LEGAL_WORKFLOW_ENABLED: 'false',
      GRPC_ENABLED: 'false',
      GDPR_DELETION_ENABLED: 'true',
      GDPR_GRACE_PERIOD: '720h',
    };
    secrets.push(...secretEnvironmentValues(apiEnvironment));
    for (const [index, port] of apiPorts.entries()) {
      start(
        `API replica ${index + 1}`,
        apiBinary,
        [],
        { ...apiEnvironment, PORT: String(port) },
        backend
      );
    }
    startNotifier();
    start(
      'Next production',
      process.execPath,
      [
        resolve(workspace, 'node_modules/next/dist/bin/next'),
        'start',
        '--hostname',
        '127.0.0.1',
        '--port',
        String(nextPort),
      ],
      { NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1' },
      resolve(workspace, 'apps/web')
    );
    for (const [label, port, path] of [
      ['API A', apiPorts[0], '/healthz'],
      ['API B', apiPorts[1], '/healthz'],
      ['production Next', nextPort, '/login'],
    ]) {
      await waitFor(async () => {
        assert(
          children.every(({ child }) => child.exitCode === null),
          'A portal server exited during startup'
        );
        try {
          const result = await fetch(`http://127.0.0.1:${port}${path}`, {
            signal: AbortSignal.timeout(1000),
            redirect: 'error',
          });
          await result.arrayBuffer();
          return result.ok;
        } catch {
          return false;
        }
      }, label);
    }
    return { origin, tlsSPKI, fixture, mail, captureJSON, startNotifier, stopNotifier, waitForNoticeCleanup, routeEvidence, originEvidence, close, diagnostics, secrets };
  } catch (error) {
    diagnostics();
    await close();
    throw error;
  }
}
