import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const geographyFixtureMarker = 'geography-acceptance-fixture';
export const geographyFixtureRoute = '/geography-acceptance';

// This is an explicitly declared complete synthetic snapshot, never a loader for
// operator data or an automatically inferred assertion of source completeness.
export function syntheticGeography(changed = false) {
  return {
    types: [{ Id: 2, Name: 'Synthetic province' }, { Id: 3, Name: 'Synthetic district' },
      { Id: 5, Name: 'Synthetic urban area' }, { Id: 7, Name: 'Synthetic village' }],
    cities: [
      { Id: 1, Name: 'Alpha province', ParentId: null, CenterType: 2 },
      { Id: 2, Name: 'Beta province', ParentId: null, CenterType: 2 },
      { Id: 10, Name: 'Alpha district', ParentId: 1, CenterType: 3 },
      { Id: 11, Name: 'Alpha area', ParentId: 10, CenterType: 5 },
      { Id: 12, Name: 'Alpha nested area', ParentId: 11, CenterType: 5 },
      { Id: 13, Name: '\u0643\u064a\u0627\u0646\u200c\u0622\u0628\u0627\u062f', ParentId: 12, CenterType: 7 },
      { Id: 14, Name: 'Literal %_\\ locality', ParentId: 10, CenterType: 7 },
      { Id: 15, Name: 'Identical village', ParentId: 10, CenterType: 7 },
      ...(!changed ? [{ Id: 16, Name: 'Identical village', ParentId: 10, CenterType: 7 }] : []),
      { Id: 20, Name: 'Beta village', ParentId: 2, CenterType: 7 },
      ...Array.from({ length: 24 }, (_, index) => ({ Id: 100 + index,
        Name: `Page ${String(index).padStart(2, '0')}${changed && index === 23 ? ' revised' : ''}`,
        ParentId: 10, CenterType: 7 })),
    ],
  };
}

export async function writeSyntheticSnapshot(directory, baseRevision = null, changed = false) {
  const { cities, types } = syntheticGeography(changed);
  const bytes = { cities: Buffer.from(JSON.stringify(cities)), types: Buffer.from(JSON.stringify(types)) };
  const paths = Object.fromEntries(['cities', 'types', 'manifest'].map((name) => [name, resolve(directory, `${name}.json`)]));
  const manifest = {
    country: 'IR', source_release: changed ? 'synthetic-browser-v2' : 'synthetic-browser-v1',
    cities_sha256: createHash('sha256').update(bytes.cities).digest('hex'),
    types_sha256: createHash('sha256').update(bytes.types).digest('hex'),
    cities_bytes: bytes.cities.length, types_bytes: bytes.types.length,
    place_count: cities.length, type_count: types.length, province_count: 2,
    expected_current_revision: baseRevision, complete_snapshot: true,
  };
  await Promise.all([writeFile(paths.cities, bytes.cities, { mode: 0o600 }),
    writeFile(paths.types, bytes.types, { mode: 0o600 }), writeFile(paths.manifest, JSON.stringify(manifest), { mode: 0o600 })]);
  return paths;
}

export async function assertNoProductionGeographyFixture(root = resolve(workspace, 'apps/web')) {
  async function inspect(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const path = resolve(directory, entry.name);
      assert(!path.includes(geographyFixtureRoute.slice(1)), 'Geography fixture entered production routes/artifacts');
      if (entry.isDirectory()) await inspect(path);
      else if (/\.(?:[cm]?js|tsx?|json|html|rsc)$/.test(entry.name)) {
        const bytes = await readFile(path);
        assert(!bytes.includes(Buffer.from(geographyFixtureMarker)), 'Geography fixture entered production routes/artifacts');
      }
    }
  }
  await inspect(resolve(root, 'app'));
  await inspect(resolve(root, '.next'));
}

export async function createDisposableGeographyApp(directory, root = workspace) {
  assert(relative(resolve('/tmp/kilo'), resolve(directory)).split('/')[0] !== '..' &&
    resolve(directory) !== resolve('/tmp/kilo'), 'Fixture must use a run-owned temporary directory');
  const app = resolve(directory, 'apps/web');
  await mkdir(resolve(app, 'app', geographyFixtureRoute.slice(1)), { recursive: true });
  const copy = (source, target = source) => cp(resolve(root, source), resolve(directory, target), {
    recursive: true, filter: (path) => !/(?:^|\/)(?:node_modules|\.next|test-output|coverage)(?:\/|$)/.test(path) &&
      !/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(path),
  });
  // No app routes, environment files, local data, snapshots, or prior build are
  // copied. Only the component/provider's source tree and public styling enter.
  for (const path of ['apps/web/app/_components/location-selector.tsx', 'apps/web/app/_components/native-dialog.tsx',
    'apps/web/app/_lib/geography-client.ts', 'apps/web/app/fonts',
    'apps/web/app/global.css', 'apps/web/i18n', 'apps/web/messages', 'apps/web/proxy.ts',
    'apps/web/postcss.config.js', 'apps/web/tailwind.config.js', 'libs/ui/src']) await copy(path);
  await symlink(resolve(root, 'node_modules'), resolve(directory, 'node_modules'), 'dir');
  const tailwind = resolve(app, 'tailwind.config.js');
  assert((await readFile(tailwind, 'utf8')).includes('../../libs/ui/src'));
  await writeFile(resolve(app, 'package.json'), JSON.stringify({ name: 'geography-browser-disposable', private: true }));
  await writeFile(resolve(app, 'next.config.js'), `module.exports = { transpilePackages: ['@hatef/ui'], outputFileTracingRoot: ${JSON.stringify(root)} };\n`);
  await writeFile(resolve(app, 'tsconfig.json'), JSON.stringify({ compilerOptions: {
    target: 'ES2022', jsx: 'preserve', module: 'esnext', moduleResolution: 'bundler', strict: true,
    esModuleInterop: true, resolveJsonModule: true, skipLibCheck: true, noEmit: true,
    plugins: [{ name: 'next' }], paths: { '@/*': ['./*'] },
  }, include: ['next-env.d.ts', 'index.d.ts', 'app/geography-acceptance/**/*.tsx', 'app/layout.tsx', '.next/types/**/*.ts'] }));
  await writeFile(resolve(app, 'index.d.ts'), '/// <reference types="@nx/next/typings/style.d.ts" />\n');
  await writeFile(resolve(app, 'app/layout.tsx'), `import { connection } from 'next/server';
import localFont from 'next/font/local';
import './global.css';
const font = localFont({src:'./fonts/Vazirmatn[wght].woff2',display:'swap',preload:false});
export default async function Layout({children}:{children:React.ReactNode}) {
  await connection(); return <html lang="en" dir="ltr"><body className={font.className}>{children}</body></html>;
}\n`);
  await writeFile(resolve(app, `app${geographyFixtureRoute}/page.tsx`), `'use client';
import { useLayoutEffect, useState } from 'react';
import { LocationSelector } from '../_components/location-selector';
import type { LocationInput } from '../_lib/geography-client';
import { DisplayProvider } from '../../i18n/provider';
import { defaultPreferences, type Locale } from '../../i18n/config';
import { getMessagesForLocale } from '../../i18n/messages';
export default function Fixture() {
  const [locale,setLocale] = useState<Locale>('en');
  const [theme,setTheme] = useState<'light'|'dark'>('light');
  const [value,setValue] = useState<LocationInput|null>(null);
  useLayoutEffect(() => { document.documentElement.lang=locale; document.documentElement.dir=locale==='fa-IR'?'rtl':'ltr'; }, [locale]);
  return <DisplayProvider preferences={{...defaultPreferences,locale,theme}} messages={getMessagesForLocale(locale)}>
    <main id="portal-content" tabIndex={-1} className="mx-auto max-w-2xl space-y-6 p-4" data-testid="${geographyFixtureMarker}">
      <nav className="flex flex-wrap gap-2">
        <button className="min-h-11 min-w-11 border px-4" data-testid="locale-en" onClick={()=>setLocale('en')}>English</button>
        <button className="min-h-11 min-w-11 border px-4" data-testid="locale-fa-IR" onClick={()=>setLocale('fa-IR')}>\u0641\u0627\u0631\u0633\u06cc</button>
        <button className="min-h-11 min-w-11 border px-4" data-testid="theme" onClick={()=>setTheme(theme==='light'?'dark':'light')}>Light / Dark</button>
      </nav>
      <LocationSelector value={value} onChange={setValue}/>
      <output data-testid="selection" data-geography-private dir="ltr">{JSON.stringify(value)}</output>
    </main>
  </DisplayProvider>;
}\n`);
  return app;
}
