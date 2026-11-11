import assert from 'node:assert/strict';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { galleryProgress, validateGalleryManifest, galleryHTML } from './generate-page-gallery.mjs';
if (process.env.NX_PROJECT_NAME && process.env.NX_PROJECT_NAME !== 'web') process.exit(0);
process.chdir(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const runId = process.argv[2];
assert(/^[0-9]+-[0-9]+$/.test(runId), 'Unsafe review run ID');
const directory = resolve('test-output/page-gallery', runId);
const manifest = JSON.parse(await readFile(resolve(directory, 'manifest.json'), 'utf8'));
const progress = validateGalleryManifest(manifest, { complete: true });
const expected = [...manifest.jobs, ...manifest.details].filter(job => job.status === 'captured');
const actual = [];
async function files(path, prefix = '') {
  for (const item of await readdir(path, { withFileTypes: true })) {
    assert(!item.isSymbolicLink(), 'Gallery must not contain symlinks');
    if (item.isDirectory()) await files(resolve(path, item.name), prefix + item.name + '/');
    else if (item.name.endsWith('.png')) actual.push(prefix + item.name);
  }
}
await files(directory);
assert.deepEqual(actual.sort(), expected.map(job => job.path).sort(), 'PNG inventory differs from captured manifest');
const indexPath = resolve(directory, 'index.html');
// Only this newly declared run is rebuilt, never an earlier inventory/bundle.
await writeFile(indexPath, galleryHTML(manifest), { mode: 0o600 });
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  let unexpectedNetwork = 0;
  await page.route(/^https?:/, route => { unexpectedNetwork++; return route.abort(); });
  await page.goto(pathToFileURL(resolve(directory, 'index.html')).href, { waitUntil: 'load' });
   assert.equal(await page.locator('section[data-view]').count(), progress.expectedStates);
  assert.equal(await page.locator('img').count(), expected.length);
  for (const [control, value] of [['surface', 'admin'], ['device', 'mobile'], ['theme', 'dark']]) await page.locator('#' + control).selectOption(value);
  assert.equal(await page.locator('section[data-surface="admin"]:not([hidden])').count(), new Set(manifest.jobs.filter(job => job.surface === 'admin').map(job => job.id)).size);
  assert.equal(await page.locator('section:not([hidden]) .pair:not([hidden])').count(), new Set(manifest.jobs.filter(job => job.surface === 'admin' && job.device === 'mobile' && job.theme === 'dark').map(job => job.id)).size);
  for (const control of ['surface', 'device', 'theme']) await page.locator('#' + control).selectOption('all');
  await page.locator('#route').selectOption('/register');
  assert.equal(await page.locator('section:not([hidden])').count(), new Set(manifest.jobs.filter(job => job.route === '/register').map(job => job.id)).size);
  await page.locator('#route').selectOption('all');
  await page.locator('#state').selectOption('baseline');
  await page.locator('#locale').selectOption('fa-IR');
  assert.equal(await page.locator('section:not([hidden]) .pair:not([hidden]) figure:not([hidden])').count(), manifest.jobs.filter(job => job.state === 'baseline' && job.locale === 'fa-IR').length);
  for (const control of ['state', 'locale']) await page.locator('#' + control).selectOption('all');
  await page.locator('#device').selectOption('short');
  assert.equal(await page.locator('section:not([hidden]) .pair:not([hidden])').count(), new Set(manifest.jobs.filter(job => job.device === 'short').map(job => `${job.id}/${job.theme}`)).size);
  await page.locator('#device').selectOption('all');
  assert.equal(unexpectedNetwork, 0, 'Offline gallery attempted a network request');
  await page.goto('about:blank');
  let imageChecks = 0;
  for (const job of expected) {
    assert(job.synthetic === true && job.masked === false && job.demoValues && job.decoded && job.width >= job.viewport.width);
    if (job.width > job.viewport.width) assert(job.mode === 'full-page' && (job.demoOverflow || job.parent));
    const data = await readFile(resolve(directory, job.path));
    const checked = await page.evaluate(async base64 => {
      const image = await createImageBitmap(await (await fetch('data:image/png;base64,' + base64)).blob());
      const canvas = new OffscreenCanvas(image.width, image.height);
      const context = canvas.getContext('2d'); context.drawImage(image, 0, 0);
      const pixels = context.getImageData(0, 0, image.width, image.height).data;
      const colors = new Set();
      for (let i = 0; i < pixels.length; i += 4 * 17) colors.add((pixels[i] << 16) | (pixels[i + 1] << 8) | pixels[i + 2]);
      let grayCover = false;
      for (let y = 0; y < image.height && !grayCover; y += 4) {
        let run = 0;
        for (let x = 0; x < image.width; x++) {
          const i = (y * image.width + x) * 4;
          run = pixels[i] === 119 && pixels[i + 1] === 119 && pixels[i + 2] === 119 ? run + 1 : 0;
          if (run > 128) { grayCover = true; break; }
        }
      }
      const result = { width: image.width, height: image.height, nonblank: colors.size > 16, grayCover };
      image.close(); return result;
    }, data.toString('base64'));
    assert(checked.nonblank && checked.width === job.width && checked.height === job.height, 'Blank or invalid image');
    assert.equal(checked.grayCover, false, 'A gray covering rectangle remains in the image');
    imageChecks++;
  }
  const sampled = (process.argv[3] || '').split(',').filter(Boolean);
  assert(sampled.every(id => manifest.jobs.some(job => job.id === id)), 'Undeclared manual-review sample');
  manifest.review = { automated: 'passed', imageChecks, offlineGallery: 'passed', unexpectedNetwork: 0,
    progress: galleryProgress(manifest),
    privateArtifactInputs: 'readable-synthetic-demo-values-only', manualSampleIDs: sampled,
    grayCoverCheck: 'passed',
    scope: 'Automated matrix validation and selected visual inspection; exclusions remain unperformed.' };
  await writeFile(resolve(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ status: manifest.status, corePNGs: manifest.capturedPNGs, detailPNGs: manifest.detailPNGs,
    imageChecks, viewCount: progress.expectedStates, localeCounts: progress.locales, offlineGallery: 'passed', cleanup: manifest.cleanup,
    findingCategories: [...new Set(manifest.findings.map(finding => finding.category))], manualSampleCount: sampled.length }));
} finally { if (browser) await browser.close(); }
