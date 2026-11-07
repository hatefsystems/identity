import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { acceptanceIdentity } from './portal-harness.mjs';
import { getMetadata, readArtifact } from './release-images.mjs';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

// This gate deliberately cannot certify enrollment while phases 5/6 and their
// image/provider/browser acceptance are absent. It is not a replacement fixture
// flow and must be replaced by the real acceptance when those phases land.
export async function registrationBlockers({ image = process.env.REGISTRATION_BROWSER_API_IMAGE, exists = async (path) => {
  try { await access(resolve(workspace, path)); return true; } catch { return false; }
} } = {}) {
  const blockers = [];
  if (!/^sha256:[a-f0-9]{64}$/.test(image || '')) blockers.push('immutable-quality-tested-api-image');
  for (const [name, path] of [
    ['registration-service', 'apps/identity-api/internal/registration/service.go'],
    ['smsir-production-adapter', 'apps/identity-api/internal/smsotp/smsir'],
    ['smtputf8-transport', 'apps/identity-api/internal/smtptransport'],
    ['registration-cleanup-worker', 'apps/identity-api/cmd/registration-cleanup/main.go'],
    ['registration-ui', 'apps/web/app/_components/registration.tsx'],
  ]) if (!await exists(path)) blockers.push(name);
  blockers.push('production-image-isolated-provider-and-browser-acceptance');
  return { version: 1, kind: 'registration-browser', status: 'blocked', blockers };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2]) {
    assert.equal(process.argv.length, 3, 'Expected one quality artifact directory');
    const artifact = await readArtifact(process.argv[2], 'api', await getMetadata(), process.env);
    assert.deepEqual(artifact.identity, await acceptanceIdentity(), 'Quality API source/generated identity mismatch');
    process.env.REGISTRATION_BROWSER_API_IMAGE = artifact.imageId;
  }
  const report = await registrationBlockers();
  console.error(JSON.stringify(report));
  process.exitCode = 1;
}
