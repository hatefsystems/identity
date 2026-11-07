import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPOSITORY = 'hatefsystems/identity';
export const SOURCE = `https://github.com/${REPOSITORY}`;
export const PLATFORM = 'linux/amd64';
const KINDS = ['api', 'web'];
const COMMIT = /^[a-f0-9]{40}(?![\s\S])/;
const DIGEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const MANIFEST_TYPES = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
];
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));

export function parseVersion(version) {
  const match =
    typeof version === 'string' &&
    version.length <= 128 &&
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(
      version
    );
  if (!match || match[0] !== version || match[4]?.split('.').some((part) => /^0\d+$/.test(part))) {
    throw new Error(
      'Invalid release version: require strict SemVer without build metadata, at most 128 characters'
    );
  }
  return { version, stable: !match[4], parts: match.slice(1, 4).map(BigInt) };
}

export function compareStableVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a.stable || !b.stable) throw new Error('Latest must identify a stable SemVer release');
  for (let i = 0; i < 3; i++) {
    if (a.parts[i] !== b.parts[i]) return a.parts[i] > b.parts[i] ? 1 : -1;
  }
  return 0;
}

export function computeMetadata(env, revision) {
  if (!COMMIT.test(revision)) throw new Error('Checkout must resolve to a full commit SHA');
  const repository = env.GITHUB_REPOSITORY || REPOSITORY;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?![\s\S])/.test(repository))
    throw new Error('Invalid repository name');
  const tagPush = env.GITHUB_EVENT_NAME === 'push' && env.GITHUB_REF?.startsWith('refs/tags/v');
  const taggedVersion = tagPush
    ? parseVersion(env.GITHUB_REF.slice('refs/tags/v'.length)).version
    : null;
  const release = Boolean(tagPush && env.GITHUB_REPOSITORY === REPOSITORY);
  return {
    revision,
    version: release ? taggedVersion : `sha-${revision}`,
    source: `https://github.com/${repository}`,
    release,
  };
}

// Never pass the workflow token to Docker, Git, or a smoke-test child process.
export function runCommand(
  command,
  args,
  { timeout = 60_000, maxBuffer = 4 * 1024 * 1024, env = process.env } = {}
) {
  const childEnv = { ...env, GIT_TERMINAL_PROMPT: '0' };
  for (const key of [
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'ACTIONS_RUNTIME_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  ])
    delete childEnv[key];
  return new Promise((resolveCommand, reject) => {
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      detached: process.platform !== 'win32',
      env: childEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let size = 0;
    let settled = false;
    const stdout = [];
    const stderr = [];
    const stop = () => {
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.removeListener('SIGTERM', interrupted);
      process.removeListener('SIGINT', interrupted);
      if (error) reject(error);
      else resolveCommand(Buffer.concat(stdout).toString('utf8'));
    };
    const interrupted = () => {
      stop();
      finish(new Error(`${command} interrupted`));
    };
    const timer = setTimeout(() => {
      stop();
      finish(new Error(`${command} timed out`));
    }, timeout);
    process.once('SIGTERM', interrupted);
    process.once('SIGINT', interrupted);
    for (const [stream, chunks] of [
      [child.stdout, stdout],
      [child.stderr, stderr],
    ]) {
      stream.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBuffer) {
          stop();
          finish(new Error(`${command} exceeded its output limit`));
        } else chunks.push(chunk);
      });
    }
    child.once('error', () => finish(new Error(`Unable to start ${command}`)));
    child.once('close', (code) => {
      if (code === 0) finish();
      else {
        let detail = Buffer.concat(stderr).toString('utf8').slice(-2000);
        for (const key of ['GITHUB_TOKEN', 'GH_TOKEN'])
          if (env[key]) detail = detail.replaceAll(env[key], '[redacted]');
        finish(new Error(`${command} failed (exit ${code}): ${detail}`));
      }
    });
  });
}

export async function getMetadata({ env = process.env, run = runCommand } = {}) {
  return computeMetadata(
    env,
    (await run('git', ['rev-parse', '--verify', 'HEAD^{commit}'], { env })).trim()
  );
}

function requireRelease(metadata, env) {
  if (!metadata.release || !computeMetadata(env, metadata.revision).release) {
    throw new Error('Publication/export requires a canonical repository version-tag push');
  }
  if (!/^\d+(?![\s\S])/.test(env.GITHUB_RUN_ID || ''))
    throw new Error('GITHUB_RUN_ID is required to bind artifacts to this run');
}

function imageRepository(kind) {
  if (!KINDS.includes(kind)) throw new Error('Image kind must be api or web');
  return `ghcr.io/hatefsystems/identity-${kind}`;
}

function imageInfo(document, imageId = document?.Id) {
  const labels = (document?.Config || document?.config)?.Labels || {};
  return {
    imageId,
    platform: `${document?.Os || document?.os}/${document?.Architecture || document?.architecture}`,
    source: labels['org.opencontainers.image.source'],
    revision: labels['org.opencontainers.image.revision'],
    version: labels['org.opencontainers.image.version'],
  };
}

export function assertImage(image, expected = {}) {
  if (
    !image ||
    !DIGEST.test(image.imageId) ||
    image.platform !== PLATFORM ||
    image.source !== SOURCE ||
    !COMMIT.test(image.revision)
  ) {
    throw new Error(
      'Image must have a valid ID, linux/amd64 platform, and canonical OCI source/revision labels'
    );
  }
  if (image.digest !== undefined && !DIGEST.test(image.digest))
    throw new Error('Invalid registry manifest digest');
  parseVersion(image.version);
  for (const key of ['imageId', 'platform', 'source', 'revision', 'version']) {
    if (expected[key] !== undefined && image[key] !== expected[key])
      throw new Error(`Image ${key} mismatch`);
  }
}

async function inspectImage(reference, run, env) {
  const images = JSON.parse(await run('docker', ['image', 'inspect', reference], { env }));
  if (!Array.isArray(images) || images.length !== 1)
    throw new Error('Expected exactly one inspected image');
  return imageInfo(images[0]);
}

export async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

async function regularFile(path, maxSize) {
  const info = await lstat(path);
  if (!info.isFile() || !info.size || info.size > maxSize)
    throw new Error('Artifact must be a nonempty regular file within its size limit');
}

export async function exportImage(
  kind,
  reference,
  directory,
  { env = process.env, run = runCommand } = {}
) {
  imageRepository(kind);
  if (!/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,254}(?![\s\S])/.test(reference || ''))
    throw new Error('Invalid local image reference');
  const metadata = await getMetadata({ env, run });
  requireRelease(metadata, env);
  const image = await inspectImage(reference, run, env);
  assertImage(image, metadata);
  await mkdir(directory, { recursive: true });
  const archive = `${kind}.tar`;
  const path = resolve(directory, archive);
  await run('docker', ['image', 'save', '--output', path, image.imageId], {
    env,
    timeout: 600_000,
  });
  await regularFile(path, 20 * 1024 ** 3);
  const artifact = {
    kind,
    archive,
    sha256: await hashFile(path),
    ...image,
    runId: env.GITHUB_RUN_ID,
  };
  await writeFile(resolve(directory, `${kind}.json`), `${JSON.stringify(artifact, null, 2)}\n`);
  return artifact;
}

async function readArtifact(directory, kind, metadata, env) {
  const path = resolve(directory, `${kind}.json`);
  await regularFile(path, 64 * 1024);
  const artifact = JSON.parse(await readFile(path, 'utf8'));
  if (
    artifact.kind !== kind ||
    artifact.archive !== `${kind}.tar` ||
    artifact.runId !== env.GITHUB_RUN_ID ||
    !/^[a-f0-9]{64}(?![\s\S])/.test(artifact.sha256)
  ) {
    throw new Error(`Invalid ${kind} artifact metadata or workflow run ID`);
  }
  assertImage(artifact, metadata);
  const archivePath = resolve(directory, `${kind}.tar`);
  await regularFile(archivePath, 20 * 1024 ** 3);
  if ((await hashFile(archivePath)) !== artifact.sha256)
    throw new Error(`${kind} archive checksum mismatch`);
  return { ...artifact, archivePath };
}

// Bound response bodies as well as connection time. Authenticated requests never follow redirects.
async function request(url, options, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetchImpl(url, {
      ...options,
      redirect: 'manual',
      signal: controller.signal,
    });
    const chunks = [];
    let size = 0;
    if (response.body)
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) {
          controller.abort();
          throw new Error('HTTP response exceeded its size limit');
        }
        chunks.push(chunk);
      }
    return { status: response.status, headers: response.headers, body: Buffer.concat(chunks) };
  } catch {
    // Fetch errors can contain a rejected Authorization header or signed redirect URL.
    throw new Error('Release HTTP request failed, timed out, or exceeded its response limit');
  } finally {
    clearTimeout(timer);
  }
}

function json(response) {
  try {
    return JSON.parse(response.body.toString('utf8'));
  } catch {
    throw new Error('Invalid JSON from release service');
  }
}

export async function verifyReleaseTag(metadata, env, fetchImpl = globalThis.fetch) {
  if (!env.GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is required for live tag verification');
  if (!COMMIT.test(env.GITHUB_SHA || ''))
    throw new Error('GITHUB_SHA must identify the event commit');
  const get = async (path) => {
    const response = await request(
      `https://api.github.com/repos/${REPOSITORY}/git/${path}`,
      {
        headers: {
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'identity-release',
        },
      },
      fetchImpl
    );
    if (response.status !== 200)
      throw new Error(`GitHub tag verification failed (HTTP ${response.status})`);
    return json(response);
  };
  const peel = async (object) => {
    const seen = new Set();
    while (
      object?.type === 'tag' &&
      COMMIT.test(object.sha) &&
      !seen.has(object.sha) &&
      seen.size < 8
    ) {
      seen.add(object.sha);
      const tag = await get(`tags/${object.sha}`);
      if (tag.sha !== object.sha) throw new Error('Annotated tag object mismatch');
      object = tag.object;
    }
    if (object?.type !== 'commit' || !COMMIT.test(object.sha))
      throw new Error('Release tag does not resolve to a commit');
    return object.sha;
  };
  const ref = await get(`ref/tags/${encodeURIComponent(`v${metadata.version}`)}`);
  if (ref.ref !== env.GITHUB_REF || (await peel(ref.object)) !== metadata.revision)
    throw new Error('Release tag moved away from the tested commit');
  // Some tag events carry the annotated tag object rather than its peeled commit.
  const eventCommit =
    env.GITHUB_SHA === metadata.revision
      ? env.GITHUB_SHA
      : await peel({ type: 'tag', sha: env.GITHUB_SHA });
  if (eventCommit !== metadata.revision)
    throw new Error('Event commit does not match the tested checkout');
}

export class RegistryError extends Error {
  constructor(stage, response) {
    let codes = [];
    try {
      const errors = json(response).errors;
      if (Array.isArray(errors))
        codes = errors.map((error) =>
          typeof error?.code === 'string' && /^[A-Z_]+(?![\s\S])/.test(error.code)
            ? error.code
            : 'UNKNOWN'
        );
    } catch {
      /* Unknown errors remain failures. */
    }
    super(
      `GHCR ${stage} failed (HTTP ${response.status}${codes.length ? `; ${codes.join(', ')}` : ''})`
    );
    this.status = response.status;
    this.codes = codes;
  }
}

export function createRegistry(env, fetchImpl = globalThis.fetch) {
  const token = async (kind, anonymous) => {
    const name = imageRepository(kind).slice('ghcr.io/'.length);
    const headers = {};
    if (!anonymous) {
      if (!env.GITHUB_TOKEN || !env.GITHUB_ACTOR)
        throw new Error('GITHUB_TOKEN and GITHUB_ACTOR are required for GHCR');
      headers.Authorization = `Basic ${Buffer.from(`${env.GITHUB_ACTOR}:${env.GITHUB_TOKEN}`).toString('base64')}`;
    }
    const query = new URLSearchParams({
      service: 'ghcr.io',
      scope: `repository:${name}:${anonymous ? 'pull' : 'pull,push'}`,
    });
    const response = await request(`https://ghcr.io/token?${query}`, { headers }, fetchImpl);
    if (response.status !== 200) throw new RegistryError('token exchange', response);
    const payload = json(response);
    const value = payload.token || payload.access_token;
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value))
      throw new Error('GHCR returned no usable bearer token');
    return { name, headers: { Authorization: `Bearer ${value}` } };
  };
  const checkDigest = (body, expected) => {
    const actual = `sha256:${createHash('sha256').update(body).digest('hex')}`;
    if (expected && expected !== actual) throw new Error('Registry content digest mismatch');
    return actual;
  };
  return {
    async read(kind, reference, { anonymous = false } = {}) {
      if (reference !== 'latest' && !DIGEST.test(reference)) parseVersion(reference);
      const { name, headers } = await token(kind, anonymous);
      const response = await request(
        `https://ghcr.io/v2/${name}/manifests/${reference}`,
        { headers: { ...headers, Accept: MANIFEST_TYPES.join(', ') } },
        fetchImpl
      );
      if (response.status !== 200) {
        const error = new RegistryError('manifest read', response);
        // GHCR also returns MANIFEST_UNKNOWN for a never-published package. DENIED is not absence.
        if (
          response.status === 404 &&
          error.codes.length === 1 &&
          error.codes[0] === 'MANIFEST_UNKNOWN'
        )
          return null;
        throw error;
      }
      const digest = checkDigest(response.body, DIGEST.test(reference) ? reference : undefined);
      if (
        response.headers.get('docker-content-digest') &&
        response.headers.get('docker-content-digest') !== digest
      )
        throw new Error('Registry digest header mismatch');
      const manifest = json(response);
      const mediaType = manifest.mediaType || response.headers.get('content-type')?.split(';')[0];
      if (
        manifest.schemaVersion !== 2 ||
        !MANIFEST_TYPES.includes(mediaType) ||
        !DIGEST.test(manifest.config?.digest) ||
        !Array.isArray(manifest.layers) ||
        !manifest.layers.every((layer) => DIGEST.test(layer.digest))
      ) {
        throw new Error('Expected a single-platform OCI or Docker v2 image manifest');
      }
      let blob = await request(
        `https://ghcr.io/v2/${name}/blobs/${manifest.config.digest}`,
        { headers },
        fetchImpl
      );
      // GHCR can redirect blobs to signed CDN URLs. Never forward credentials to the CDN.
      for (
        let redirects = 0;
        [301, 302, 303, 307, 308].includes(blob.status) && redirects < 3;
        redirects++
      ) {
        const location = new URL(blob.headers.get('location'));
        if (location.protocol !== 'https:' || location.username || location.password)
          throw new Error('Unsafe registry blob redirect');
        blob = await request(location.href, { headers: {} }, fetchImpl);
      }
      if (blob.status !== 200) throw new RegistryError('config read', blob);
      checkDigest(blob.body, manifest.config.digest);
      return {
        ...imageInfo(json(blob), manifest.config.digest),
        digest,
        manifest: response.body,
        mediaType,
      };
    },
    async promote(kind, image) {
      checkDigest(image.manifest, image.digest);
      const { name, headers } = await token(kind, false);
      const response = await request(
        `https://ghcr.io/v2/${name}/manifests/latest`,
        {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': image.mediaType },
          body: image.manifest,
        },
        fetchImpl
      );
      if (response.status !== 201) throw new RegistryError('latest promotion', response);
      if (
        response.headers.get('docker-content-digest') &&
        response.headers.get('docker-content-digest') !== image.digest
      )
        throw new Error('Latest promotion digest mismatch');
    },
  };
}

export function formatSummary(summary) {
  const lines = [
    '## Container Release',
    '',
    `Source: ${summary.source}`,
    `Revision: \`${summary.revision}\``,
    `Version: \`${summary.version}\``,
    `Platform: \`${PLATFORM}\``,
    '',
    '| Image | Version Result | Version Digest | Previous Latest | Observed Latest | Alias Result | Anonymous Access |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const image of summary.images) {
    lines.push(
      `| ${image.kind} | ${image.versionResult} | ${image.digest || 'not verified'} | ${image.oldLatest} | ${image.newLatest} | ${image.aliasResult} | ${image.visibility} |`
    );
  }
  lines.push('', '### Pull Commands', '', '```sh');
  for (const image of summary.images) {
    lines.push(`docker pull ${imageRepository(image.kind)}:${summary.version}`);
    if (image.digest) lines.push(`docker pull ${imageRepository(image.kind)}@${image.digest}`);
  }
  lines.push(
    '```',
    '',
    'Public access is verified separately from publication. Newly created GHCR packages start private; an administrator must review image contents, set BOTH packages Public, and confirm repository Actions access. This helper never changes visibility or deletes images.'
  );
  if (summary.error)
    lines.push(
      '',
      `Release failed; partial registry state is retained for a safe rerun: ${summary.error}`
    );
  return `${lines.join('\n')}\n`;
}

async function writeSummary(summary, env) {
  const text = formatSummary(summary);
  console.log(text);
  if (summary.images.some((image) => image.visibility.startsWith('not public')))
    console.log(
      '::warning::GHCR public access needs administrator bootstrap; this is not yet an anonymously usable release.'
    );
  if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, text);
}

export async function publishImages(
  directory,
  {
    env = process.env,
    run = runCommand,
    fetchImpl = globalThis.fetch,
    registry = createRegistry(env, fetchImpl),
    report = (summary) => writeSummary(summary, env),
  } = {}
) {
  const metadata = await getMetadata({ env, run });
  requireRelease(metadata, env);
  const summary = {
    ...metadata,
    images: KINDS.map((kind) => ({
      kind,
      versionResult: 'not attempted',
      digest: null,
      oldLatest: 'not checked',
      newLatest: 'not checked',
      aliasResult: 'not attempted',
      visibility: 'not checked',
    })),
  };
  try {
    await verifyReleaseTag(metadata, env, fetchImpl);
    const artifacts = await Promise.all(
      KINDS.map((kind) => readArtifact(directory, kind, metadata, env))
    );
    for (const artifact of artifacts) {
      await run('docker', ['image', 'load', '--input', artifact.archivePath], {
        env,
        timeout: 600_000,
      });
      assertImage(await inspectImage(artifact.imageId, run, env), artifact);
    }
    // Check BOTH version names before writing either; an unrelated existing image is never replaced.
    const existing = await Promise.all(KINDS.map((kind) => registry.read(kind, metadata.version)));
    existing.forEach((image, index) => {
      if (!image) return;
      assertImage(image, artifacts[index]);
      summary.images[index].digest = image.digest;
      summary.images[index].versionResult = 'existing; content verified';
    });
    await verifyReleaseTag(metadata, env, fetchImpl);
    const published = [];
    for (let i = 0; i < KINDS.length; i++) {
      const state = summary.images[i];
      const versionRef = `${imageRepository(state.kind)}:${metadata.version}`;
      let image = existing[i];
      if (!image) {
        await run('docker', ['image', 'tag', artifacts[i].imageId, versionRef], { env });
        state.versionResult = 'push attempted; outcome unknown';
        await run('docker', ['image', 'push', '--platform', PLATFORM, versionRef], {
          env,
          timeout: 600_000,
        });
        image = await registry.read(state.kind, metadata.version);
        assertImage(image, artifacts[i]);
      }
      state.digest = image.digest;
      state.versionResult = existing[i] ? 'reused' : 'published';
      published.push(image);
      const digestRef = `${imageRepository(state.kind)}@${image.digest}`;
      await run('docker', ['image', 'pull', '--platform', PLATFORM, digestRef], {
        env,
        timeout: 600_000,
      });
      assertImage(await inspectImage(digestRef, run, env), artifacts[i]);
      await run(
        process.execPath,
        [join(SCRIPT_DIRECTORY, 'smoke-image.mjs'), state.kind, digestRef],
        { env, timeout: 300_000 }
      );
      state.versionResult += '; digest smoke passed';
    }
    for (let i = 0; i < KINDS.length; i++) {
      const state = summary.images[i];
      try {
        for (const reference of [metadata.version, published[i].digest]) {
          const image = await registry.read(state.kind, reference, { anonymous: true });
          assertImage(image, artifacts[i]);
          if (image.digest !== published[i].digest)
            throw new Error('Anonymous version/digest mismatch');
        }
        const dockerConfig = await mkdtemp(join(tmpdir(), 'identity-ghcr-public-'));
        try {
          for (const reference of [
            `${imageRepository(state.kind)}:${metadata.version}`,
            `${imageRepository(state.kind)}@${published[i].digest}`,
          ]) {
            await run(
              'docker',
              ['--config', dockerConfig, 'image', 'pull', '--platform', PLATFORM, reference],
              { env, timeout: 600_000 }
            );
          }
        } finally {
          await rm(dockerConfig, { recursive: true, force: true });
        }
        state.visibility = 'public: anonymous version/digest pulls verified';
      } catch (error) {
        if (
          !(error instanceof RegistryError) ||
          ![401, 403].includes(error.status) ||
          !error.codes.length ||
          !error.codes.every((code) => ['DENIED', 'UNAUTHORIZED'].includes(code))
        )
          throw error;
        state.visibility = 'not public: administrator bootstrap/access review required';
      }
    }
    if (!parseVersion(metadata.version).stable) {
      for (const state of summary.images) state.aliasResult = 'unchanged: prerelease';
      return summary;
    }
    const aliases = await Promise.all(KINDS.map((kind) => registry.read(kind, 'latest')));
    const order = aliases.map((image, i) => {
      const state = summary.images[i];
      state.oldLatest = image?.digest || 'absent';
      state.newLatest = state.oldLatest;
      if (!image) return -1;
      assertImage(image);
      const comparison = compareStableVersions(image.version, metadata.version);
      if (comparison === 0) {
        assertImage(image, artifacts[i]);
        if (image.digest !== published[i].digest)
          throw new Error('Equal latest version has conflicting content');
      }
      return comparison;
    });
    if (order.some((comparison) => comparison > 0)) {
      for (const state of summary.images)
        state.aliasResult = 'unchanged: newer stable release exists';
      return summary;
    }
    await verifyReleaseTag(metadata, env, fetchImpl);
    for (let i = 0; i < KINDS.length; i++) {
      const state = summary.images[i];
      if (order[i] === 0) {
        state.aliasResult = 'reused';
        continue;
      }
      state.aliasResult = 'promotion attempted; outcome unknown';
      state.newLatest = 'unknown';
      await registry.promote(state.kind, published[i]);
      const image = await registry.read(state.kind, 'latest');
      assertImage(image, artifacts[i]);
      if (image.digest !== published[i].digest)
        throw new Error('Latest did not resolve to the verified version digest');
      state.newLatest = image.digest;
      state.aliasResult = 'advanced';
    }
    return summary;
  } catch (error) {
    summary.error = error.message;
    // A timeout can follow a successful registry write. Report observations without guessing or rolling back.
    for (const state of summary.images) {
      if (state.versionResult === 'push attempted; outcome unknown') {
        try {
          const image = await registry.read(state.kind, metadata.version);
          state.digest = image?.digest || null;
          state.versionResult = image
            ? 'present after interrupted push; verification incomplete'
            : 'absent after failed push';
        } catch {
          /* Preserve unknown state when the registry cannot be read. */
        }
      }
      if (state.aliasResult === 'promotion attempted; outcome unknown') {
        try {
          state.newLatest = (await registry.read(state.kind, 'latest'))?.digest || 'absent';
        } catch {
          /* Preserve unknown state; the next authorized rerun must preflight again. */
        }
      }
    }
    throw error;
  } finally {
    await report(summary);
  }
}

export async function main(args = process.argv.slice(2), env = process.env, dependencies = {}) {
  if (args[0] === 'metadata' && args.length === 1) {
    const metadata = await getMetadata({ ...dependencies, env });
    if (env.GITHUB_OUTPUT)
      await appendFile(
        env.GITHUB_OUTPUT,
        `${Object.entries(metadata)
          .map(([key, value]) => `${key}=${value}`)
          .join('\n')}\n`
      );
    console.log(JSON.stringify(metadata));
  } else if (args[0] === 'export' && args.length === 4) {
    console.log(
      JSON.stringify(await exportImage(args[1], args[2], args[3], { ...dependencies, env }))
    );
  } else if (args[0] === 'publish' && args.length === 2) {
    await publishImages(args[1], { ...dependencies, env });
  } else {
    throw new Error(
      'Usage: release-images.mjs metadata | export <api|web> <local-image-ref> <directory> | publish <directory>'
    );
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
