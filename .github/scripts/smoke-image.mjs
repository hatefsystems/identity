import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

function docker(args, allowFailure = false) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: 45_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    throw new Error(`docker ${args[0]} failed: ${result.stderr || result.stdout}`);
  }
  return result;
}

export function maintenanceSucceeded(result, binary = '') {
  if (result.status !== 1) return false;
  if (binary === 'migrate') {
    return result.stderr.trim() === 'migrate: migrate: DATABASE_URL is empty';
  }
  return `${result.stdout}\n${result.stderr}`.split('\n').some((line) => {
    try {
      return JSON.parse(line).level === 'ERROR';
    } catch {
      return false;
    }
  });
}

function* htmlElements(html) {
  // Inspect generated tags, not comments or tag-like strings inside Flight/raw-text bodies.
  const tags = /<!--[\s\S]*?-->|<![^>]*>|<\/?([a-z][\w:-]*)\b((?:[^"'<>]|"[^"]*"|'[^']*')*)>/gi;
  let match;
  while ((match = tags.exec(html))) {
    if (!match[1] || match[0].startsWith('</')) continue;
    const tag = match[1].toLowerCase();
    const attributes = new Map();
    const attributePattern = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+)))?/g;
    for (const [, name, doubleQuoted, singleQuoted, unquoted] of match[2].matchAll(
      attributePattern
    )) {
      const key = name.toLowerCase();
      assert(!attributes.has(key), `Duplicate ${key} attribute on <${tag}>`);
      const value = (doubleQuoted ?? singleQuoted ?? unquoted ?? '').replace(
        /&(#(?:x[\da-f]+|\d+)|amp|quot|apos|lt|gt);/gi,
        (_entity, code) => {
          const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' };
          if (!code.startsWith('#')) return named[code.toLowerCase()];
          const hex = code[1].toLowerCase() === 'x';
          const point = Number.parseInt(code.slice(hex ? 2 : 1), hex ? 16 : 10);
          return point > 0 && point <= 0x10ffff ? String.fromCodePoint(point) : '\ufffd';
        }
      );
      attributes.set(key, value);
    }
    yield { tag, attributes };
    if (/^(?:script|style|textarea|title|xmp|iframe|noembed|noframes|noscript)$/.test(tag)) {
      const closing = new RegExp(`</${tag}\\s*>`, 'gi');
      closing.lastIndex = tags.lastIndex;
      assert(closing.exec(html), `Unclosed <${tag}> element`);
      tags.lastIndex = closing.lastIndex;
    }
  }
}

export function staticAssets(html) {
  const assets = new Set();
  for (const { tag, attributes } of htmlElements(html)) {
    if (tag !== 'link' && tag !== 'script') continue;
    for (const key of ['src', 'href']) {
      const value = attributes.get(key);
      if (!value?.startsWith('/_next/static/')) continue;
      const url = new URL(value, 'http://localhost');
      if (
        url.origin === 'http://localhost' &&
        url.pathname.startsWith('/_next/static/') &&
        /\.(?:css|js)$/.test(url.pathname)
      ) {
        assets.add(url.pathname + url.search);
      }
    }
  }
  assert(
    [...assets].some((path) => new URL(path, 'http://localhost').pathname.endsWith('.css')),
    'No CSS asset in page'
  );
  assert(
    [...assets].some((path) => new URL(path, 'http://localhost').pathname.endsWith('.js')),
    'No JS asset in page'
  );
  return [...assets];
}

export function webDocumentNonce(headers, html, seenNonces = new Set()) {
  const policy = headers.get('content-security-policy');
  assert(policy, 'Missing enforcing Content-Security-Policy');
  // Fetch joins duplicate header fields with commas; this policy never permits a comma.
  assert(!/[,\r\n]/.test(policy), 'Expected exactly one single-line enforcing CSP');
  assert.equal(
    headers.get('content-security-policy-report-only'),
    null,
    'Unexpected report-only CSP'
  );
  assert.equal(headers.get('x-nonce'), null, 'Do not expose a separate response x-nonce');
  const directives = new Map();
  for (const directive of policy.split(';')) {
    if (!directive.trim()) continue;
    const [name, ...sources] = directive.trim().split(/\s+/);
    const key = name.toLowerCase();
    assert(!directives.has(key), `Duplicate CSP directive: ${key}`);
    directives.set(key, sources);
  }
  const nonceSources = (directives.get('script-src') || []).filter((source) =>
    source.startsWith("'nonce-")
  );
  assert.equal(nonceSources.length, 1, 'Expected one script nonce source');
  assert.match(nonceSources[0], /^'nonce-[A-Za-z\d+/]{43}='$/, 'Nonce must be 32 bytes of base64');
  const nonce = nonceSources[0].slice(7, -1);
  assert.equal(
    Buffer.from(nonce, 'base64').toString('base64'),
    nonce,
    'Non-canonical base64 nonce'
  );
  const expected = {
    'default-src': ["'self'"],
    'script-src': ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"],
    'script-src-attr': ["'none'"],
    'style-src': ["'self'", `'nonce-${nonce}'`],
    'style-src-attr': ["'none'"],
    'connect-src': ["'self'"],
    'img-src': ["'self'"],
    'font-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'frame-src': ["'none'"],
    'upgrade-insecure-requests': [],
  };
  assert.deepEqual(
    [...directives.keys()].sort(),
    Object.keys(expected).sort(),
    'Production CSP directives'
  );
  for (const [name, sources] of Object.entries(expected)) {
    assert.deepEqual([...directives.get(name)].sort(), [...sources].sort(), `Production ${name}`);
  }
  const cache = (headers.get('cache-control') || '')
    .toLowerCase()
    .split(',')
    .map((part) => part.trim());
  assert(
    cache.includes('private') && cache.includes('no-store'),
    'HTML must be private and no-store'
  );
  assert(!cache.includes('public'), 'HTML must not be publicly cacheable');
  assert(
    !cache.some((part) => /^(?:s-maxage|max-age)\s*=\s*"?[1-9]\d*/.test(part)),
    'HTML must not have a positive cache lifetime'
  );
  assert.match(headers.get('content-type') || '', /^text\/html\b/i, 'Document MIME type');

  let executableScripts = 0;
  for (const { tag, attributes } of htmlElements(html)) {
    assert(!attributes.has('style'), `Inline style attribute on <${tag}>`);
    assert(
      ![...attributes.keys()].some((name) => /^on/i.test(name)),
      `Inline event handler on <${tag}>`
    );
    if (attributes.has('nonce'))
      assert.equal(attributes.get('nonce'), nonce, `Mismatched <${tag}> nonce`);
    const type = (attributes.get('type') || '').trim().toLowerCase();
    const executable =
      tag === 'script' &&
      (!type ||
        /^(?:module|importmap|speculationrules|(?:text|application)\/(?:x-)?(?:java|ecma)script|text\/(?:javascript1\.[0-5]|jscript|livescript))$/.test(
          type
        ));
    if (executable || tag === 'style') {
      assert.equal(attributes.get('nonce'), nonce, `Missing or mismatched <${tag}> nonce`);
      if (executable) executableScripts++;
    }
  }
  assert(executableScripts > 0, 'No executable scripts in HTML');
  assert(!seenNonces.has(nonce), 'Document nonce was reused across responses');
  seenNonces.add(nonce);
  return nonce;
}

export function assertStaticAssetHeaders(headers, path) {
  for (const name of [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-nonce',
  ]) {
    assert.equal(headers.get(name), null, `${path} must not have per-request ${name}`);
  }
  if (!path.startsWith('/_next/static/')) return;
  const cache = (headers.get('cache-control') || '')
    .toLowerCase()
    .split(',')
    .map((part) => part.trim());
  assert(
    cache.includes('public') && cache.includes('immutable'),
    `${path} must stay publicly immutable`
  );
  assert(
    cache.some((part) => /^max-age=[1-9]\d*$/.test(part)),
    `${path} must have a positive cache lifetime`
  );
  assert(
    !cache.some((part) => ['private', 'no-store', 'no-cache'].includes(part)),
    `${path} must remain cacheable`
  );
}

export async function smokeImage(kind, reference, validateWeb) {
  assert(['api', 'web'].includes(kind), 'Expected api or web image kind');
  assert(
    reference && !reference.startsWith('-') && !/\s/.test(reference),
    'Invalid image reference'
  );
  assert(
    validateWeb === undefined || typeof validateWeb === 'function',
    'Invalid web validation callback'
  );
  const [image] = JSON.parse(docker(['image', 'inspect', reference]).stdout);
  assert.equal(image.Os, 'linux');
  assert.equal(image.Architecture, 'amd64');
  const imageID = image.Id;

  if (kind === 'api') {
    assert.equal(image.Config.User, 'nonroot:nonroot');
    for (const binary of [
      'identity-api',
      'audit-signer',
      'purge-worker',
      'migrate',
      'security-ledger-purge',
      'admin-audit-publisher',
      'admin-legal',
    ]) {
      const name = `ci-api-${randomUUID()}`;
      try {
        const result = docker(
          [
            'run',
            '--name',
            name,
            '--pull',
            'never',
            '--network',
            'none',
            '--env',
            'APP_ENV=production',
            '--entrypoint',
            `/usr/local/bin/${binary}`,
            imageID,
            ...(binary === 'migrate' ? ['status'] : []),
          ],
          true
        );
        assert(
          maintenanceSucceeded(result, binary),
          `${binary} must reject missing production configuration with exit 1: ${result.stdout}${result.stderr}`
        );
      } finally {
        docker(['rm', '--force', name], true);
      }
    }
  } else {
    const uid = docker([
      'run',
      '--rm',
      '--pull',
      'never',
      '--network',
      'none',
      '--entrypoint',
      'node',
      imageID,
      '-p',
      'process.getuid()',
    ]).stdout.trim();
    assert(/^\d+$/.test(uid) && Number(uid) !== 0, 'Web image must run as a non-root UID');
    const name = `ci-web-${randomUUID()}`;
    try {
      docker([
        'run',
        '--detach',
        '--name',
        name,
        '--pull',
        'never',
        '--publish',
        '127.0.0.1::3000',
        imageID,
      ]);
      const [container] = JSON.parse(docker(['inspect', name]).stdout);
      const [port] = container.NetworkSettings.Ports['3000/tcp'];
      assert.equal(port.HostIp, '127.0.0.1');
      const base = `http://127.0.0.1:${port.HostPort}`;
      const request = (path) =>
        fetch(base + path, { redirect: 'error', signal: AbortSignal.timeout(5_000) });
      const deadline = Date.now() + 60_000;
      let html;
      let landingResponse;
      let lastError;
      while (Date.now() < deadline) {
        try {
          const response = await request('/');
          assert.equal(response.status, 200, 'Landing page HTTP status');
          html = await response.text();
          landingResponse = response;
          break;
        } catch (error) {
          lastError = error;
          await setTimeout(250);
        }
      }
      assert(html, `Web startup timed out: ${lastError}`);
      assert.match(html, /<h1\b[^>]*>Hatef Identity Platform<\/h1>/);
      const seenNonces = new Set();
      webDocumentNonce(landingResponse.headers, html, seenNonces);
      const assets = new Set(staticAssets(html));
      const notFoundPaths = [`/__csp-smoke-${randomUUID()}`, `/__csp-smoke-${randomUUID()}.html`];
      for (const path of ['/', ...notFoundPaths, ...notFoundPaths]) {
        const response = await request(path);
        assert.equal(response.status, path === '/' ? 200 : 404, `${path} HTTP status`);
        const document = await response.text();
        webDocumentNonce(response.headers, document, seenNonces);
        assert.match(
          document,
          path === '/'
            ? /<h1\b[^>]*>Hatef Identity Platform<\/h1>/
            : /<h1\b[^>]*>Page not found<\/h1>/
        );
        for (const asset of staticAssets(document)) assets.add(asset);
      }
      for (const path of ['/favicon.ico', ...assets]) {
        const response = await request(path);
        assert.equal(response.status, 200, `${path} HTTP status`);
        assertStaticAssetHeaders(response.headers, path);
        const contentType = response.headers.get('content-type') || '';
        const pathname = new URL(path, base).pathname;
        if (pathname.endsWith('.css')) assert.match(contentType, /text\/css/);
        if (pathname.endsWith('.js')) assert.match(contentType, /(?:java|ecma)script/);
        if (pathname.endsWith('.ico')) assert.match(contentType, /image\//);
        assert((await response.arrayBuffer()).byteLength > 0, `${path} is empty`);
      }
      if (validateWeb) await validateWeb({ baseURL: base, notFoundPaths });
      docker(['stop', '--time', '10', name]);
      const [stopped] = JSON.parse(docker(['inspect', name]).stdout);
      assert.equal(stopped.State.Running, false);
      assert.equal(stopped.State.OOMKilled, false);
      assert(
        [0, 143].includes(stopped.State.ExitCode),
        `Web did not stop gracefully: ${stopped.State.ExitCode}`
      );
    } catch (error) {
      const logs = docker(['logs', name], true);
      console.error(logs.stdout + logs.stderr);
      throw error;
    } finally {
      docker(['rm', '--force', name], true);
    }
  }
  console.log(`${kind} image smoke checks passed: ${reference}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  smokeImage(process.argv[2], process.argv[3]).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
