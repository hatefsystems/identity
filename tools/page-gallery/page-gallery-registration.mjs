import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { acceptanceIdentity, assertIdentity, exportAcceptanceImage, loadAcceptanceImage } from '../../.github/scripts/acceptance-report.mjs';
import { assertOnlyPreferenceCookies, browserLocales, configureBrowserPreferences, localizedText, setBrowserLocale } from '../../.github/scripts/browser-localization.mjs';
import { acceptanceLifecycle, assertLocalOrigin } from '../../.github/scripts/portal-harness.mjs';
import { registrationFailureDetails, runtimeInputs, startRegistrationHarness, trustRegistrationFixtureCA } from '../../.github/scripts/registration-browser.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const preparedImages = new WeakMap();
const root = '/api/v1/auth/register';
const masks = ['bdi', 'time', '[data-registration-feedback] [dir="ltr"]'];
const proxyKeys = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'];
const diagnostics = new WeakMap();
const stages = new Set([
  'runtime-safety', 'source-identity', 'temporary-directory', 'api-build', 'post-build-identity',
  'api-export', 'archive-permissions', 'api-load', 'controller-image',
  'postgres-image', 'redis-image', 'nats-image', 'final-identity', 'runtime-inputs',
  'fixture-docker-environment', 'harness-start', 'fixture-ca', 'browser-launch', 'context-preferences', 'probe-ready',
]);

async function stage(name, operation, probe = false) {
  assert(stages.has(name), 'Undeclared registration preparation stage');
  if (probe) console.log(JSON.stringify({ check: 'registration-gallery-prerequisite', stage: name, status: 'starting' }));
  try {
    const value = await operation();
    if (probe) console.log(JSON.stringify({ check: 'registration-gallery-prerequisite', stage: name, status: 'passed' }));
    return value;
  } catch (error) {
    const detail = diagnostics.get(error) || { category: 'validation-or-prerequisite' };
    const harness = name === 'harness-start' ? registrationFailureDetails(error) : undefined;
    console.log(JSON.stringify({ check: 'registration-gallery-prerequisite', stage: name, status: 'failed', ...detail,
      ...(harness ? { harnessStage: harness.failure_stage, harnessCheck: harness.failure_check, cleanupCompleted: harness.cleanup.completed } : {}) }));
    throw error;
  }
}

// Docker diagnostics never reach the console or bundle. Bound both pipes even
// when only inventory JSON is needed; abort/timeout reaps the owned child.
function docker(args, { timeout = 120_000, lifecycle } = {}) {
  lifecycle?.check();
  const budget = Math.max(1, Math.min(timeout, lifecycle?.remaining() ?? timeout));
  return new Promise((resolveResult, reject) => {
    const child = spawn('docker', args, {
      cwd: workspace, shell: false, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const collect = (args[0] === 'image' && ['inspect', 'ls'].includes(args[1])) ||
      (args[0] === 'context' && args[1] === 'inspect');
    const chunks = [];
    let bytes = 0, category = 'process-exit', buildOperation = 'unknown', failed = false, killTimer, diagnosticWindow = '';
    const stop = () => {
      failed = true;
      child.kill('SIGTERM');
      killTimer ??= setTimeout(() => child.kill('SIGKILL'), 1000);
    };
    const timer = setTimeout(() => { category = 'process-timeout'; stop(); }, budget);
    const signal = lifecycle?.signal;
    signal?.addEventListener('abort', stop, { once: true });
    if (signal?.aborted) { category = 'interrupted'; stop(); }
    const classify = chunk => {
      diagnosticWindow = (diagnosticWindow + chunk.toString('utf8')).slice(-8192);
      for (const [pattern, value] of [
        [/load metadata for /i, 'base-image'],
        [/go (?:-C [^\s]+ )?mod download/i, 'dependency-download'],
        [/buf generate|sqlc generate/i, 'generation'],
        [/go build -trimpath/i, 'compile'],
      ]) if (pattern.test(diagnosticWindow)) buildOperation = value;
      for (const [pattern, value] of [
        [/permission denied.*docker|cannot connect to the docker daemon/i, 'docker-unavailable'],
        [/connection refused/i, 'connection-refused'],
        [/proxyconnect/i, 'proxy-unavailable'],
        [/no such host|temporary failure in name resolution/i, 'dns-unavailable'],
        [/i\/o timeout|context deadline exceeded|TLS handshake timeout/i, 'network-timeout'],
        [/x509:|certificate signed by unknown authority/i, 'certificate-untrusted'],
        [/no space left on device/i, 'storage-exhausted'],
        [/unauthorized:|authentication required|pull access denied/i, 'registry-authorization'],
        [/failed to compute cache key|failed to calculate checksum|not found.*checksum/i, 'build-input-unavailable'],
        [/403 Forbidden|unexpected status.*403/i, 'http-forbidden'],
        [/429 Too Many|too many requests/i, 'registry-rate-limited'],
        [/could not read Username|terminal prompts disabled/i, 'module-source-authorization'],
        [/missing go.sum|updates to go.mod needed|no required module provides package/i, 'module-input-unavailable'],
        [/requires go >=|go.mod requires go/i, 'go-toolchain-unavailable'],
        [/network is unreachable|connection reset|unexpected EOF/i, 'network-unavailable'],
        [/syntax error|undefined:|cannot use .* as /i, 'compile-failure'],
      ]) if (pattern.test(diagnosticWindow)) category = value;
    };
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 16 * 1024 * 1024) { category = 'output-budget'; stop(); }
      else if (collect) chunks.push(chunk);
      else classify(chunk);
    });
    child.stderr.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 16 * 1024 * 1024) { category = 'output-budget'; stop(); }
      else classify(chunk);
    });
    child.on('error', () => { failed = true; category = 'process-start'; });
    child.once('close', (code, exitSignal) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      signal?.removeEventListener('abort', stop);
      if (failed || code !== 0 || exitSignal) {
        const error = new Error('Gallery Docker prerequisite failed; private diagnostics suppressed.');
        diagnostics.set(error, { category, exit: Number.isInteger(code) ? code : null,
          ...(args[0] === 'build' ? { buildOperation } : {}) });
        reject(error);
      }
      else resolveResult(Buffer.concat(chunks).toString('utf8'));
    });
  });
}

async function prepareImage(api) {
  const lifecycle = acceptanceLifecycle({ timeout: 45 * 60_000 });
  const owner = randomBytes(16).toString('hex');
  const reference = `identity-page-gallery:${owner}`;
  let directory, directoryIdentity, attempted = false, closing, finish;
  const finished = new Promise(resolveFinished => { finish = resolveFinished; });
  const close = () => closing ||= (async () => {
    let failed = false;
    if (attempted) {
      try {
        // Remove only our unique tag, never an externally supplied digest/tag.
        const existing = await docker(['image', 'ls', '--quiet', '--no-trunc', reference], { timeout: 30_000 });
        if (existing.trim()) {
          const [image] = JSON.parse(await docker(['image', 'inspect', reference], { timeout: 30_000 }));
          assert.equal(image.Config.Labels?.['ldp.gallery.run'], owner, 'Refusing foreign gallery image cleanup');
          await docker(['image', 'rm', reference], { timeout: 30_000 });
          assert.equal((await docker(['image', 'ls', '--quiet', '--no-trunc', reference], { timeout: 30_000 })).trim(), '', 'Gallery image tag survived cleanup');
        }
      } catch { failed = true; }
    }
    if (directory) try {
      const current = await lstat(directory);
      assert(current.isDirectory() && !current.isSymbolicLink() && current.uid === process.getuid() &&
        (current.mode & 0o777) === 0o700 && current.ino === directoryIdentity.ino && current.dev === directoryIdentity.dev,
      'Refusing foreign gallery archive cleanup');
      await rm(directory, { recursive: true });
    } catch { failed = true; }
    assert(!failed, 'Gallery image/archive cleanup failed; private diagnostics suppressed.');
  })();
  // Also preserve a failed preparer's cleanup result for the shared manifest.
  // Waiting for preparation prevents teardown from racing an in-flight build.
  api.cleanups.push(async () => { await finished; await close(); });
  try {
    const probe = api.registrationProbe === true;
    const step = (name, operation) => stage(name, operation, probe);
    const identity = await step('source-identity', () => acceptanceIdentity());
    const identify = async () => {
      const current = await acceptanceIdentity();
      assertIdentity(current, identity);
      return current;
    };
    directory = await step('temporary-directory', async () => {
      assert.equal(process.platform, 'linux', 'Gallery fixtures require Linux or WSL2');
      directory = await mkdtemp(resolve(tmpdir(), 'page-gallery-registration-'));
      directoryIdentity = await lstat(directory);
      assert(directoryIdentity.isDirectory() && directoryIdentity.uid === process.getuid() && (directoryIdentity.mode & 0o777) === 0o700);
      return directory;
    });
    const run = (command, args, options = {}) => {
      assert.equal(command, 'docker', 'Unexpected image preparation executable');
      return docker(args, { ...options, lifecycle });
    };
    attempted = true;
    // Keep the configured forwarding proxy: direct module downloads may be
    // denied. On Linux only this build needs host networking to reach a host-
    // loopback proxy; production fixtures still use their private owned network.
    const loopbackProxy = proxyKeys.some(key => {
      try { return ['localhost', '127.0.0.1', '[::1]'].includes(new URL(process.env[key]).hostname); }
      catch { return false; }
    });
    const networkArgs = loopbackProxy && process.platform === 'linux' ? ['--network', 'host'] : [];
    if (probe) console.log(JSON.stringify({ check: 'registration-gallery-build-network', loopbackProxy, buildOnlyHostNetwork: networkArgs.length > 0 }));
    await step('api-build', () => run('docker', [
      'build', '--platform', 'linux/amd64', '--file', 'apps/identity-api/Dockerfile',
      '--tag', reference, '--label', `org.opencontainers.image.revision=${identity.revision}`,
      '--label', `ldp.gallery.run=${owner}`, '--label', `ldp.gallery.source=${identity.source}`, ...networkArgs, '.',
    ], { timeout: 25 * 60_000 }));
    await step('post-build-identity', identify);
    await step('api-export', () => exportAcceptanceImage(reference, directory, { identify, run }));
    await step('archive-permissions', async () => {
      await chmod(resolve(directory, 'acceptance-api.tar'), 0o600);
      await chmod(resolve(directory, 'acceptance-api.json'), 0o600);
    });
    const manifest = await step('api-load', () => loadAcceptanceImage(directory, { identify, run }));
    for (const [name, image] of [['controller-image', 'node:24-bookworm-slim'], ['postgres-image', 'postgres:16-alpine'], ['redis-image', 'redis:7-alpine'], ['nats-image', 'nats:2.10-alpine']]) {
      await step(name, async () => {
        try { await run('docker', ['image', 'inspect', image]); }
        catch { await run('docker', ['pull', image], { timeout: 600_000 }); }
      });
    }
    await step('final-identity', identify);
    return { directory, identity, image: manifest.imageId };
  } catch {
    await close();
    throw new Error('Registration gallery image preparation unavailable; private diagnostics suppressed.');
  } finally {
    lifecycle.release();
    finish();
  }
}

function imageFor(api) {
  if (!preparedImages.has(api)) {
    // The next locale still needs the checksum-bound tar. It stays outside the
    // bundle and is removed, together with the owned image tag, at run teardown.
    preparedImages.set(api, prepareImage(api));
  }
  return preparedImages.get(api);
}

function remember(harness, value) {
  // Owned RP ID and WebAuthn requirement enums are reviewed public metadata,
  // not private authorities; startup legitimately logs these exact values.
  if (typeof value === 'string' && !['localhost', 'required'].includes(value)) harness.remember(value);
  else if (value && typeof value === 'object') for (const child of Object.values(value)) remember(harness, child);
}

async function until(lifecycle, operation, timeout = 15_000) {
  const end = Date.now() + Math.min(timeout, lifecycle.remaining());
  while (Date.now() < end) {
    lifecycle.check();
    if (await operation()) return;
    await delay(100, undefined, { signal: lifecycle.signal });
  }
  throw new Error('Registration gallery state unavailable.');
}

export async function registrationPhase(api) {
  await stage('runtime-safety', () => {
    assert(browserLocales.includes(api.locale), 'Unsupported registration gallery locale');
    const flags = ['DEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'PWDEBUG'].filter(key => process.env[key]);
    if (flags.length || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
      const error = new Error('Registration gallery rejects unsafe diagnostics/TLS settings.');
      diagnostics.set(error, { category: flags.length ? 'unsafe-diagnostics' : 'unsafe-tls', flags });
      throw error;
    }
  }, api.registrationProbe === true);
  setBrowserLocale(api.locale);
  const image = await imageFor(api);
  const step = (name, operation) => stage(name, operation, api.registrationProbe === true);
  await step('source-identity', async () => assertIdentity(await acceptanceIdentity(), image.identity));
  const lifecycle = acceptanceLifecycle({ timeout: 20 * 60_000 });
  let harness, browser, context;
  const owned = [];
  const own = operation => {
    let result;
    const dispose = () => result ||= Promise.resolve().then(operation);
    owned.push(dispose);
    api.cleanups.push(dispose);
  };
  own(() => lifecycle.release());
  const close = async () => {
    let failed = false;
    for (const dispose of [...owned].reverse()) await dispose().catch(() => { failed = true; });
    assert(!failed, 'Registration gallery phase cleanup failed; private diagnostics suppressed.');
  };
  try {
    const inputs = await step('runtime-inputs', () => runtimeInputs({
      ...process.env, REGISTRATION_BROWSER_API_IMAGE: image.image,
      REGISTRATION_BROWSER_API_MANIFEST: resolve(image.directory, 'acceptance-api.json'),
      REGISTRATION_BROWSER_ARTIFACT_DIR: image.directory,
      REGISTRATION_BROWSER_CONTROLLER_IMAGE: 'node:24-bookworm-slim',
    }));
    own(await step('fixture-docker-environment', async () => {
      const endpoint = process.env.DOCKER_HOST && !process.env.DOCKER_CONTEXT ? { Host: process.env.DOCKER_HOST } :
        JSON.parse(await docker(['context', 'inspect', '--format', '{{json .Endpoints.docker}}'], { timeout: 30_000 }));
      assert(typeof endpoint.Host === 'string' && endpoint.Host.startsWith('unix://'), 'Registration fixture requires a local Docker socket');
      const config = resolve(image.directory, 'fixture-docker-config');
      await mkdir(config, { recursive: true, mode: 0o700 });
      await writeFile(resolve(config, 'config.json'), '{}\n', { mode: 0o600 });
      // Docker client config silently injects proxy variables into every create,
      // including private services. No registry credentials are copied. Preserve
      // the selected local socket, and restore the caller's environment last.
      const keys = ['DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_CONTEXT'];
      const original = keys.map(key => process.env[key]);
      process.env.DOCKER_CONFIG = config;
      process.env.DOCKER_HOST = endpoint.Host;
      delete process.env.DOCKER_CONTEXT;
      return () => {
        for (const [index, key] of keys.entries()) {
          if (original[index] === undefined) delete process.env[key];
          else process.env[key] = original[index];
        }
      };
    }));
    try {
      harness = await step('harness-start', () => startRegistrationHarness(inputs, lifecycle, image.identity));
    } catch (error) {
      if (!registrationFailureDetails(error).cleanup.completed) {
        own(() => { throw new Error('Registration startup cleanup was not confirmed.'); });
      }
      throw error;
    }
    api.privateValues = () => [...harness.secrets];
    own(async () => assert.equal((await harness.close())?.completed, true));
    assertLocalOrigin(harness.origin);
    own(await step('fixture-ca', () => trustRegistrationFixtureCA(harness.tlsCA, harness.tlsCAPath)));
    browser = await step('browser-launch', () => chromium.launch({
      headless: true, timeout: Math.min(60_000, lifecycle.remaining()),
      args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`],
    }));
    own(() => browser.close());
    lifecycle.check();
    context = await browser.newContext({
      serviceWorkers: 'block', bypassCSP: false, reducedMotion: 'reduce',
      viewport: { width: 1280, height: 900 },
    });
    api.contexts.add(context);
    own(async () => { await context.close(); api.contexts.delete(context); });
    context.setDefaultTimeout(15_000);
    context.setDefaultNavigationTimeout(30_000);
    const interrupted = () => { void close().catch(() => {}); };
    lifecycle.signal.addEventListener('abort', interrupted, { once: true });
    await step('context-preferences', async () => {
      await configureBrowserPreferences(context, harness.origin, api.locale);
      assertOnlyPreferenceCookies(await context.cookies(harness.origin));
    });

    // Narrow opt-in diagnosis: real HTTPS documents only, no signup mutation,
    // message delivery, screenshots, or acceptance report.
    if (api.registrationProbe === true) {
      await step('probe-ready', async () => {
        const page = await context.newPage();
        const response = await page.goto(harness.origin + '/register');
        assert.equal(response?.status(), 200);
        await page.getByRole('heading', { name: localizedText('Create your account'), exact: true }).waitFor();
        await until(lifecycle, () => page.getByRole('button', { name: localizedText('Start registration and send email'), exact: true }).isEnabled());
        assert.equal(await page.locator('html').getAttribute('lang'), api.locale);
        assert.equal(await page.locator('html').getAttribute('dir'), api.locale === 'fa-IR' ? 'rtl' : 'ltr');
        const summary = await harness.control('/summary');
        assert(summary.mail === 0 && summary.sms === 0 && summary.violations === 0);
        harness.assertPrivateLogs();
      });
      return;
    }

    const failures = new Set();
    const pending = new Set();
    context.on('page', page => {
      page.on('pageerror', () => failures.add('runtime'));
      page.on('download', () => failures.add('download'));
      page.on('console', message => {
        const text = message.text();
        if (/hydration|Content Security Policy/i.test(text) || [...harness.secrets].some(secret => text.includes(secret))) failures.add('console');
      });
    });
    context.on('request', request => {
      try {
        const url = new URL(request.url());
        assert.equal(url.origin, harness.origin);
        if (!url.pathname.startsWith(root)) return;
        assert(!url.search && !url.hash, 'Registration authority entered request URL');
        const headers = request.headers();
        assert(headers.dpop && !headers.cookie && !headers.authorization && !headers.referer);
        remember(harness, headers.dpop);
        remember(harness, request.postDataJSON());
      } catch { failures.add('request'); }
    });
    context.on('response', response => {
      const url = new URL(response.url());
      if (!url.pathname.startsWith(root) || response.status() === 204) return;
      const work = (async () => {
        const headers = await response.allHeaders();
        assert(!headers['set-cookie'] && /\bno-store\b/.test(headers['cache-control'] || '') && headers['referrer-policy'] === 'no-referrer');
        if (/json/.test(headers['content-type'] || '')) remember(harness, await harness.registrationResponse(response));
      })().catch(() => { failures.add('response'); });
      pending.add(work);
      void work.finally(() => pending.delete(work));
    });

    const button = (page, label) => page.getByRole('button', { name: localizedText(label), exact: true });
    const status = (page, text) => page.locator('[data-registration-feedback]').getByRole('status').filter({ hasText: localizedText(text) });
    const enabled = async (page, label) => {
      const target = button(page, label);
      await target.waitFor();
      await until(lifecycle, () => target.isEnabled());
      return target;
    };
    const document = async (page, path, heading) => {
      await page.bringToFront();
      const response = await page.goto(harness.origin + path);
      assert.equal(response?.status(), 200, 'Registration gallery document unavailable');
      await page.getByRole('heading', { name: localizedText(heading), exact: true }).waitFor();
      assert.equal(await page.locator('html').getAttribute('lang'), api.locale);
      assert.equal(await page.locator('html').getAttribute('dir'), api.locale === 'fa-IR' ? 'rtl' : 'ltr');
      if (path.startsWith('/register/verify-email')) {
        const title = localizedText('Verify registration email | Hatef Identity');
        await until(lifecycle, async () => typeof title === 'string' ? await page.title() === title : title.test(await page.title()));
      }
    };
    const capture = async (page, id) => {
      lifecycle.check();
      await Promise.all([...pending]);
      assert.equal(failures.size, 0, 'Registration gallery browser/privacy prerequisite failed');
      await api.capture(page, id, {
        heading: api.views.find(view => view.id === id).heading,
        sensitiveSelectors: masks, sensitive: true, role: 'anonymous',
      });
    };
    const action = async (page, path, expectedStatus, operation) => {
      lifecycle.check();
      const [response] = await Promise.all([
        page.waitForResponse(response => new URL(response.url()).pathname === root + path &&
          response.request().method() === 'POST' && response.status() !== 401),
        operation(),
      ]);
      assert.equal(response.status(), expectedStatus, 'Registration gallery operation unavailable');
      if (expectedStatus === 204) return;
      const value = await harness.registrationResponse(response);
      remember(harness, value);
      return value;
    };
    const take = async (path, filter) => {
      let proof;
      await until(lifecycle, async () => {
        proof = await harness.control(path, filter);
        if (proof) remember(harness, proof);
        return Boolean(proof);
      });
      return proof;
    };

    const page = await context.newPage();
    let registrationReady = false, started, verification, verificationReady = false;
    let emailConfirmed = false, phoneReady = false, smsReady = false, passkeyReady = false, contacts, smsProof;
    await api.group(['register-baseline'], async () => {
      await document(page, '/register', 'Create your account');
      await enabled(page, 'Start registration and send email');
      registrationReady = true;
      await capture(page, 'register-baseline');
    });
    await api.group(['verify-email-baseline'], async () => {
      const baseline = await context.newPage();
      try {
        await document(baseline, '/register/verify-email', 'Email verification unavailable');
        await baseline.locator('[data-registration-feedback]').getByRole('alert').filter({
          hasText: localizedText('This link cannot be verified here. Use the original browser, or restart registration. The link cannot recover signup authority.'),
        }).waitFor();
        assert.equal(await button(baseline, 'Verify email ownership').isEnabled(), false);
        assert.equal(new URL(baseline.url()).hash, '');
        await capture(baseline, 'verify-email-baseline');
      } finally { await baseline.close(); }
    });
    await api.group(['register-native-input'], async () => {
      assert(registrationReady, 'Registration baseline unavailable');
      await page.bringToFront();
      const suffix = randomBytes(8).toString('hex');
      const email = `gallery-${suffix}@example.test`;
      const phone = '091' + String(randomBytes(4).readUInt32BE() % 100_000_000).padStart(8, '0');
      remember(harness, { email, phone });
      await page.getByLabel(localizedText('Email address'), { exact: true }).fill(email);
      const nativePhone = phone.replace(/[0-9]/g, (digit, index) => String.fromCharCode((index % 2 ? 0x0660 : 0x06f0) + Number(digit)));
      await page.getByLabel(localizedText('Iranian mobile number'), { exact: true }).fill(nativePhone);
      assert.equal(await page.getByLabel(localizedText('Iranian mobile number'), { exact: true }).inputValue(), phone);
      contacts = { email, phone };
      await capture(page, 'register-native-input');
    });
    await api.group(['register-email-pending'], async () => {
      assert(contacts, 'Registration native-input state unavailable');
      const { phone } = contacts;
      const result = await action(page, '/start', 201, () => button(page, 'Start registration and send email').click());
      assert(result.email_sent === true && typeof result.canonical_email === 'string' &&
        /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(result.attempt_id) &&
        /^[A-Za-z0-9_-]{43}$/.test(result.capability));
      await status(page, 'Verification email accepted for delivery. Open its link in this browser and explicitly confirm it. No account exists yet.').waitFor();
      await enabled(page, 'Check email verification');
      assert.equal(await page.getByText(result.canonical_email, { exact: true }).getAttribute('dir'), 'ltr');
      const summary = await harness.control('/summary');
      assert(summary.mail === 1 && summary.sms === 0 && summary.violations === 0);
      started = { ...result, phone };
      await capture(page, 'register-email-pending');
    });
    await api.group(['verify-email-ready'], async () => {
      assert(started, 'Registration email unavailable');
      const proof = await take('/take-mail', { recipient: started.canonical_email });
      assert.equal(proof.attempt_id, started.attempt_id, 'Registration email crossed attempts');
      const link = new URL(proof.link);
      assert(link.origin === harness.origin && link.pathname === '/register/verify-email' && !link.search &&
        link.hash === `#attempt_id=${proof.attempt_id}&token=${proof.token}`, 'Unexpected registration proof link');
      verification = await context.newPage();
      await document(verification, link.pathname + link.hash, 'Verify your email ownership');
      await until(lifecycle, () => new URL(verification.url()).hash === '');
      await enabled(verification, 'Verify email ownership');
      verificationReady = true;
      await capture(verification, 'verify-email-ready');
    });
    await api.group(['verify-email-confirmed'], async () => {
      assert(verificationReady, 'Registration verification link unavailable');
      await verification.bringToFront();
      await action(verification, '/email/verify', 204, () => button(verification, 'Verify email ownership').click());
      await status(verification, 'Email ownership is verified. This did not create an account or sign you in. This page cannot recover signup authority.').waitFor();
      await verification.getByText(localizedText('Return to the original registration tab and choose Check email verification there.'), { exact: true }).waitFor();
      assert.equal(new URL(verification.url()).hash, '');
      assert.equal(await button(verification, 'Verify email ownership').count(), 0);
      emailConfirmed = true;
      await capture(verification, 'verify-email-confirmed');
    });
    await api.group(['register-phone-ready'], async () => {
      assert(emailConfirmed, 'Registration email confirmation unavailable');
      await page.bringToFront();
      const result = await action(page, '/result', 200, () => button(page, 'Check email verification').click());
      assert(result.email_verified === true && result.phone_verified === false && result.state === 'pending' && result.expires_at === started.expires_at);
      await status(page, 'Email ownership is verified. Request an SMS when you are ready.').waitFor();
      await enabled(page, 'Send SMS code');
      assert.equal((await harness.control('/summary')).sms, 0);
      phoneReady = true;
      await capture(page, 'register-phone-ready');
    });
    await api.group(['register-sms-code'], async () => {
      assert(phoneReady, 'Registration phone step unavailable');
      const sent = await action(page, '/phone/send', 200, () => button(page, 'Send SMS code').click());
      assert(/^[A-Za-z0-9_-]{43}$/.test(sent.verification_id));
      await page.getByLabel(localizedText('SMS verification code'), { exact: true }).waitFor();
      await enabled(page, 'Verify phone');
      await status(page, 'SMS accepted for delivery. Enter the six-digit code to prove ownership; delivery alone does not verify your phone.').waitFor();
      assert.equal((await harness.control('/summary')).sms, 1);
      smsReady = true;
      await capture(page, 'register-sms-code');
    });
    await api.group(['register-sms-native-digits'], async () => {
      assert(smsReady, 'Registration SMS step unavailable');
      smsProof = await take('/take-sms', { mobile: started.phone.slice(1) });
      assert(/^[0-9]{6}$/.test(smsProof.code));
      const nativeCode = smsProof.code.replace(/[0-9]/g, (digit, index) => String.fromCharCode((index % 2 ? 0x0660 : 0x06f0) + Number(digit)));
      await page.getByLabel(localizedText('SMS verification code'), { exact: true }).fill(nativeCode);
      assert.equal(await page.getByLabel(localizedText('SMS verification code'), { exact: true }).inputValue(), smsProof.code);
      await capture(page, 'register-sms-native-digits');
    });
    await api.group(['register-passkey-ready'], async () => {
      assert(smsReady, 'Registration SMS step unavailable');
      const sms = smsProof;
      assert(sms, 'Registration native SMS state unavailable');
      assert(/^[0-9]{6}$/.test(sms.code));
      await page.getByLabel(localizedText('SMS verification code'), { exact: true }).fill(sms.code);
      await action(page, '/phone/verify', 204, () => button(page, 'Verify phone').click());
      await status(page, 'Phone ownership is verified. Create a discoverable passkey with a device PIN or biometrics.').waitFor();
      await enabled(page, 'Create passkey and complete registration');
      passkeyReady = true;
      await capture(page, 'register-passkey-ready');
    });
    await api.group(['register-completed'], async () => {
      assert(passkeyReady, 'Registration passkey step unavailable');
      const cdp = await context.newCDPSession(page);
      let authenticatorId;
      try {
        await cdp.send('WebAuthn.enable');
        ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
          options: {
            protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
            hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
            automaticPresenceSimulation: true,
          },
        }));
        const result = await action(page, '', 200, () => button(page, 'Create passkey and complete registration').click());
        assert(result.state === 'completed' && result.next === 'login' && result.email_verified === true && result.phone_verified === true);
        await status(page, 'Your account was created. Sign in with your passkey to continue. Registration did not sign you in.').waitFor();
        await page.getByRole('link', { name: localizedText('Sign in with your passkey'), exact: true }).waitFor();
        assert.equal(await button(page, 'Create passkey and complete registration').count(), 0);
        assertOnlyPreferenceCookies(await context.cookies(harness.origin));
        const summary = await harness.control('/summary');
        assert(summary.mail === 1 && summary.sms === 1 && summary.violations === 0);
        await capture(page, 'register-completed');
      } finally {
        if (authenticatorId) await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
        await cdp.detach();
      }
    });
    await Promise.all([...pending]);
    assert.equal(failures.size, 0, 'Registration gallery browser/privacy prerequisite failed');
    try { harness.assertPrivateLogs(); }
    catch { api.finding('service-log-privacy-guard', 'registration'); }
    assertIdentity(await acceptanceIdentity(), image.identity);
    lifecycle.signal.removeEventListener('abort', interrupted);
  } finally {
    await close();
  }
}
