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

export function staticAssets(html) {
  const assets = new Set();
  for (const [, value] of html.matchAll(/(?:src|href)=["']([^"']+)["']/g)) {
    if (!value.startsWith('/_next/static/')) continue;
    const url = new URL(value.replaceAll('&amp;', '&'), 'http://localhost');
    if (
      url.origin === 'http://localhost' &&
      url.pathname.startsWith('/_next/static/') &&
      /\.(?:css|js)$/.test(url.pathname)
    ) {
      assets.add(url.pathname + url.search);
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

export async function smokeImage(kind, reference) {
  assert(['api', 'web'].includes(kind), 'Expected api or web image kind');
  assert(
    reference && !reference.startsWith('-') && !/\s/.test(reference),
    'Invalid image reference'
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
      let lastError;
      while (Date.now() < deadline) {
        try {
          const response = await request('/');
          assert.equal(response.status, 200, 'Landing page HTTP status');
          html = await response.text();
          break;
        } catch (error) {
          lastError = error;
          await setTimeout(250);
        }
      }
      assert(html, `Web startup timed out: ${lastError}`);
      assert.match(html, /<h1\b[^>]*>Hatef Identity Platform<\/h1>/);
      for (const path of ['/favicon.ico', ...staticAssets(html)]) {
        const response = await request(path);
        assert.equal(response.status, 200, `${path} HTTP status`);
        const contentType = response.headers.get('content-type') || '';
        const pathname = new URL(path, base).pathname;
        if (pathname.endsWith('.css')) assert.match(contentType, /text\/css/);
        if (pathname.endsWith('.js')) assert.match(contentType, /(?:java|ecma)script/);
        if (pathname.endsWith('.ico')) assert.match(contentType, /image\//);
        assert((await response.arrayBuffer()).byteLength > 0, `${path} is empty`);
      }
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
