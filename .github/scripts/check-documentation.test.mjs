import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseMarkdown,
  headingAnchors,
  validateLinks,
  validateBacklog,
  checkDocumentation,
} from './check-documentation.mjs';

test('anchors retain Unicode, inline-code text, duplicate suffixes and explicit IDs', () => {
  const ast = parseMarkdown(
    '# Café `API` / V1\n\n# Café `API` / V1\n\n# فارسی\n\n<a id="exact"></a>'
  );
  assert.deepEqual([...headingAnchors(ast)], ['café-api--v1', 'café-api--v1-1', 'فارسی', 'exact']);
});

test('generated anchor suffixes never collide with literal suffixed headings', () => {
  assert.deepEqual(
    [...headingAnchors(parseMarkdown('# X\n\n# X\n\n# X-1'))],
    ['x', 'x-1', 'x-1-1']
  );
});

async function linkFixture(t, source, target = '# Target\n') {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-links-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'docs'));
  await writeFile(join(root, 'docs/target.md'), target);
  const ast = parseMarkdown(source);
  const documents = new Map([
    ['docs/source.md', { ast }],
    ['docs/target.md', { ast: parseMarkdown(target) }],
  ]);
  return validateLinks('docs/source.md', ast, documents, root);
}

test('relative and reference-style links validate paths and anchors without network access', async (t) => {
  const result = await linkFixture(
    t,
    '[Target](target.md#target)\n\n[Ref][target]\n\n[target]: target.md#target\n\n[Official](https://example.test/)'
  );
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, { links: 3, anchors: 2 });
});

test('missing anchors and missing targets are rejected', async (t) => {
  const result = await linkFixture(
    t,
    '[Bad](target.md#absent)\n\n[Absent](missing.md)\n\n[Ref][missing]'
  );
  assert(result.errors.some((error) => error.includes('Missing local Markdown anchor')));
  assert(result.errors.some((error) => error.includes('Missing local link target')));
});

test('unresolved reference nodes cannot silently evade link validation', () => {
  const ast = parseMarkdown('');
  ast.children.push({ type: 'linkReference', identifier: 'missing' });
  const result = validateLinks('docs/test.md', ast, new Map(), process.cwd());
  assert.deepEqual(result.errors, ['docs/test.md:1 Unresolved reference-style link']);
});

test('only the explicitly generated JSON output may be a not-yet-existing report link', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-report-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'docs'));
  const ast = parseMarkdown('[Report](report.json)\n\n[Other](other.json)');
  const result = validateLinks(
    'docs/test.md',
    ast,
    new Map(),
    root,
    join(root, 'docs/report.json')
  );
  assert.deepEqual(result.errors, ['docs/test.md:3 Missing local link target']);
});

test('a pending report cannot escape through a parent-directory symlink', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-report-root-'));
  const outside = await mkdtemp(join(tmpdir(), 'identity-document-report-outside-'));
  t.after(() =>
    Promise.all([
      rm(root, { recursive: true, force: true }),
      rm(outside, { recursive: true, force: true }),
    ])
  );
  await mkdir(join(root, 'docs'));
  await symlink(outside, join(root, 'docs/out'), 'junction');
  const result = validateLinks(
    'docs/test.md',
    parseMarkdown('[Report](out/report.json)'),
    new Map(),
    root,
    join(root, 'docs/out/report.json')
  );
  assert(result.errors.some((error) => error.includes('Report parent escapes')));
});

test('otherwise-public symlinks may not resolve into ignored private content', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-private-alias-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'docs'));
  await mkdir(join(root, '.kilo/plans'), { recursive: true });
  await writeFile(join(root, '.kilo/plans/private.md'), '# private fixture');
  await symlink(join(root, '.kilo/plans/private.md'), join(root, 'docs/public.md'), 'file');
  const result = validateLinks(
    'docs/test.md',
    parseMarkdown('[Alias](public.md)'),
    new Map(),
    root
  );
  assert(result.errors.some((error) => error.includes('outside shared checkout content')));
});

test('absolute links inside the current checkout still fail portability', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-absolute-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, 'target.md'), '# Target');
  const result = validateLinks(
    'test.md',
    parseMarkdown(`[Absolute](${join(root, 'target.md')})`),
    new Map(),
    root
  );
  assert(result.errors.some((error) => error.includes('Absolute local links are not portable')));
});

test('ignored agent documents cannot become authoritative links even if present', async (t) => {
  const result = await linkFixture(
    t,
    '[Private](../.kilo/plans/private.md)\n\n[Encoded](../%2ekilo/plans/private.md)'
  );
  assert.equal(result.errors.length, 2);
  assert(result.errors.every((error) => error.includes('private or outside-checkout')));
});

test('absolute, traversal and unsupported local protocols fail before opening private files', async (t) => {
  const result = await linkFixture(
    t,
    '[Outside](/tmp/private.md)\n\n[Traversal](../../private.md)\n\n[File](file:///private.md)'
  );
  assert.equal(result.errors.length, 3);
});

test('invalid URL escapes fail rather than throwing out of the checker', async (t) => {
  const result = await linkFixture(t, '[Bad](target.md#%ZZ)');
  assert(result.errors.some((error) => error.includes('Invalid link encoding')));
});

const labels = [
  'ID/title',
  'Objective',
  'Scope',
  'Explicit out of scope',
  'Dependencies',
  'Security invariants',
  'Authorization requirements',
  'Functional acceptance',
  'Security acceptance',
  'Unit tests',
  'Database/HTTP integration tests',
  'Concurrency/failure tests',
  'Browser/accessibility tests',
  'Documentation updates',
  'Completion criteria',
];
const letters = new Map([
  ['Functional acceptance', 'F'],
  ['Security acceptance', 'S'],
  ['Unit tests', 'U'],
  ['Database/HTTP integration tests', 'I'],
  ['Concurrency/failure tests', 'X'],
  ['Browser/accessibility tests', 'B'],
  ['Documentation updates', 'D'],
  ['Completion criteria', 'C'],
]);
function record(id, dependencies = 'None') {
  return `### ${id}\n\n| Section | Requirement |\n| --- | --- |\n${labels
    .map((label) => {
      const value =
        label === 'ID/title'
          ? `${id} - task`
          : label === 'Dependencies'
            ? dependencies
            : letters.has(label)
              ? `${id}-${letters.get(label)}01: observable requirement`
              : 'Bounded requirement';
      return `| ${label} | ${value} |`;
    })
    .join('\n')}\n`;
}
function backlog({
  first = record('T01'),
  second = record('T02', 'T01'),
  inventory = 'T02',
  waves = '| 0 | T01 |\n| 1 | T02 |',
} = {}) {
  const primary = Array.from({ length: 42 }, (_, index) => {
    const id = `T${String(index + 1).padStart(2, '0')}`;
    return `| ${id} | ${id === 'T01' ? id : id === 'T02' ? inventory : 'None'} |`;
  }).join('\n');
  return parseMarkdown(
    `| Primary ID | Executable nodes |\n| --- | --- |\n${primary}\n\n| Wave | Executable nodes |\n| --- | --- |\n${waves}\n\n${first}\n${second}`
  );
}

test('task inventory validates all sections, stable criteria and earlier dependency waves', () => {
  const result = validateBacklog(backlog());
  assert.deepEqual(result.errors, []);
  assert.equal(result.ids.size, 42);
  assert.deepEqual(result.counts, {
    executableRecords: 2,
    taskSections: 30,
    criteria: 16,
    dependencyEdges: 1,
  });
});

test('a missing section is not hidden by otherwise valid record length', () => {
  const result = validateBacklog(
    backlog({
      first: record('T01').replace('| Unit tests | T01-U01: observable requirement |\n', ''),
    })
  );
  assert(result.errors.some((error) => error.includes('exactly 15 sections')));
  assert(result.errors.some((error) => error.includes('missing Unit tests')));
});

test('backup task criteria cannot impersonate another task or factor', () => {
  const result = validateBacklog(
    backlog({ second: record('T02', 'T01').replace('T02-S01:', 'T01-S01:') })
  );
  assert(result.errors.some((error) => error.includes('T02 missing stable Security acceptance')));
});

test('dependency cycles and reversed waves are explicit failures', () => {
  const result = validateBacklog(backlog({ first: record('T01', 'T02') }));
  assert(result.errors.some((error) => error.includes('Dependency cycle')));
  assert(result.errors.some((error) => error.includes('earlier wave')));
});

test('aggregate and excluded nodes cannot substitute for executable dependencies', () => {
  const result = validateBacklog(backlog({ second: record('T02', 'T12') }));
  assert(result.errors.some((error) => error.includes('missing, aggregate or excluded T12')));
});

test('duplicate records and duplicate waves are rejected', () => {
  const result = validateBacklog(
    backlog({ second: record('T01'), waves: '| 0 | T01 |\n| 1 | T01 |' })
  );
  assert(result.errors.some((error) => error.includes('Duplicate executable record')));
  assert(result.errors.some((error) => error.includes('Duplicate wave task')));
});

test('new subtasks are admitted through inventory without hardcoded record counts', () => {
  const result = validateBacklog(
    backlog({
      inventory: 'T02A',
      second: record('T02A', 'T01'),
      waves: '| 0 | T01 |\n| 1 | T02A |',
    })
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.ids.size, 43);
});

test('excluded T12 cannot be converted into an executable record', () => {
  const result = validateBacklog(
    backlog({ inventory: 'T12', second: record('T12'), waves: '| 0 | T01,T12 |' })
  );
  assert(result.errors.some((error) => error.includes('T12 must remain excluded')));
});

test('duplicate inventory membership cannot disappear into a Set', () => {
  const result = validateBacklog(backlog({ inventory: 'T02,T01' }));
  assert(
    result.errors.some((error) => error.includes('Duplicate executable inventory membership T01'))
  );
});

test('appended duplicate or wrong-task criteria are validated, not only the first prefix', () => {
  const second = record('T02', 'T01').replace(
    'T02-S01: observable requirement',
    'T02-S01: observable requirement; T02-S01: duplicate; T01-S02: impersonation'
  );
  const result = validateBacklog(backlog({ second }));
  assert(result.errors.some((error) => error.includes('Duplicate criterion identifier T02-S01')));
  assert(
    result.errors.some((error) => error.includes('Wrong-task or malformed criterion T01-S02'))
  );
});

test('additional unique criteria remain supported and counted', () => {
  const second = record('T02', 'T01').replace(
    'T02-S01: observable requirement',
    'T02-S01: observable requirement; T02-S02: another observable outcome'
  );
  const result = validateBacklog(backlog({ second }));
  assert.deepEqual(result.errors, []);
  assert.equal(result.counts.criteria, 17);
});

async function checkoutFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'identity-document-checkout-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'docs'), { recursive: true });
  await mkdir(join(root, '.github/tasks'), { recursive: true });
  const policy = `| ID | Rule |\n| --- | --- |\n${Array.from({ length: 16 }, (_, index) => `| SEC${String(index + 1).padStart(2, '0')} | Invariant |`).join('\n')}\n\n\`\`\`mermaid\nflowchart TD\n A --> B\n\`\`\`\n`;
  await writeFile(join(root, 'docs/authentication-and-recovery-policy.md'), policy);
  await writeFile(join(root, 'README.md'), '[Policy](docs/authentication-and-recovery-policy.md)');
  await writeFile(join(root, 'tasks.md'), 'Historical task roadmap');
  // Serialize the same bounded fixture used by the structural unit tests.
  const primary = Array.from({ length: 42 }, (_, index) => {
    const id = `T${String(index + 1).padStart(2, '0')}`;
    return `| ${id} | ${index < 2 ? id : 'None'} |`;
  }).join('\n');
  await writeFile(
    join(root, '.github/tasks/registration-single-contract-tasks.md'),
    `| Primary ID | Nodes |\n| --- | --- |\n${primary}\n\n| Wave | Nodes |\n| --- | --- |\n| 0 | T01 |\n| 1 | T02 |\n\n${record('T01')}\n${record('T02', 'T01')}`
  );
  return root;
}

test('references-only mode works without agent folders, Git metadata or temporary tooling', async (t) => {
  const root = await checkoutFixture(t);
  const result = await checkDocumentation({ root, referencesOnly: true });
  assert.deepEqual(result.failures, []);
  assert.equal(result.sourceCommit, null);
  assert.equal(result.status, 'passed');
  assert.equal(result.diagrams.status, 'not-run');
  assert.equal(result.counts.diagrams, 1);
});

test('full mode fails closed when diagram tooling is absent', async (t) => {
  const root = await checkoutFixture(t);
  const result = await checkDocumentation({ root });
  assert.equal(result.status, 'failed');
  assert.equal(result.diagrams.status, 'failed');
  assert(result.failures.includes('Pinned isolated Mermaid tooling unavailable or invalid'));
});

test('historical identifiers with human-readable dates do not become current dependencies', async (t) => {
  const root = await checkoutFixture(t);
  const filename = join(root, 'docs/authentication-and-recovery-policy.md');
  const source = await readFile(filename, 'utf8');
  await writeFile(
    filename,
    `${source}\n## Acceptance, November 6, 2026\n\nHistorical ID: \`.kilo/plans/old.md\`.\n`
  );
  const result = await checkDocumentation({ root, referencesOnly: true });
  assert.deepEqual(result.failures, []);
});

test('active guidance cannot point at local agent state', async (t) => {
  const root = await checkoutFixture(t);
  const filename = join(root, 'docs/authentication-and-recovery-policy.md');
  await writeFile(
    filename,
    `${await readFile(filename, 'utf8')}\n## Current setup\n\nRead \`.kilo/plans/current.md\` to run this project.\n`
  );
  const result = await checkDocumentation({ root, referencesOnly: true });
  assert(
    result.failures.some((failure) => failure.includes('Active guidance depends on local agent'))
  );
});

test('historical labeling never waives a broken or private clickable link', async (t) => {
  const root = await checkoutFixture(t);
  const filename = join(root, 'docs/authentication-and-recovery-policy.md');
  await writeFile(
    filename,
    `${await readFile(filename, 'utf8')}\n## Acceptance, November 6, 2026\n\n[Private](../.kilo/plans/old.md)\n`
  );
  const result = await checkDocumentation({ root, referencesOnly: true });
  assert(result.failures.some((failure) => failure.includes('Link requires private')));
});

test('top-level document aliases cannot expose ignored private data', async (t) => {
  const root = await checkoutFixture(t);
  await mkdir(join(root, '.kilo'), { recursive: true });
  await writeFile(join(root, '.kilo/private.md'), 'private fixture');
  await rm(join(root, 'README.md'));
  await symlink(join(root, '.kilo/private.md'), join(root, 'README.md'), 'file');
  await assert.rejects(
    checkDocumentation({ root, referencesOnly: true }),
    /Document file is outside shared checkout content/
  );
});

test('document-directory symlinks cannot redirect scans into ignored state', async (t) => {
  const root = await checkoutFixture(t);
  await mkdir(join(root, '.kilo'), { recursive: true });
  await rename(join(root, 'docs'), join(root, '.kilo/docs'));
  await symlink(join(root, '.kilo/docs'), join(root, 'docs'), 'junction');
  await assert.rejects(
    checkDocumentation({ root, referencesOnly: true }),
    /Document directory is outside shared checkout content/
  );
});

test('source-citation aliases are confined before source bytes are read', async (t) => {
  const root = await checkoutFixture(t);
  await mkdir(join(root, 'apps/identity-api/internal'), { recursive: true });
  await mkdir(join(root, '.kilo'), { recursive: true });
  await writeFile(join(root, '.kilo/private.go'), 'private fixture');
  await symlink(
    join(root, '.kilo/private.go'),
    join(root, 'apps/identity-api/internal/example.go'),
    'file'
  );
  const policy = join(root, 'docs/authentication-and-recovery-policy.md');
  await writeFile(policy, `${await readFile(policy, 'utf8')}\n\`internal/example.go:1\`\n`);
  const result = await checkDocumentation({ root, referencesOnly: true });
  assert(
    result.failures.some((error) =>
      error.includes('Current cited source is outside shared checkout content')
    )
  );
});

for (const mode of ['node_modules', 'package', 'entrypoint']) {
  test(`correct-version Mermaid tooling cannot escape isolation via ${mode} symlinks`, async (t) => {
    const root = await checkoutFixture(t);
    const tools = await mkdtemp(join(tmpdir(), 'identity-document-isolated-'));
    t.after(() => rm(tools, { recursive: true, force: true }));
    const modules = join(tools, 'node_modules');
    await mkdir(modules);
    for (const [name, version, entry] of [
      ['mermaid', '11.17.2', 'dist/mermaid.core.mjs'],
      ['jsdom', '27.4.0', 'lib/api.js'],
    ]) {
      const directory = join(modules, name);
      await mkdir(join(directory, entry.split('/')[0]), { recursive: true });
      await writeFile(join(directory, 'package.json'), JSON.stringify({ version }));
      await writeFile(join(directory, entry), 'globalThis.__documentationIsolationProbe = true;');
    }
    await mkdir(join(root, 'not-isolated'));
    if (mode === 'node_modules') {
      await rename(modules, join(root, 'not-isolated/node_modules'));
      await symlink(join(root, 'not-isolated/node_modules'), modules, 'junction');
    } else if (mode === 'package') {
      await rename(join(modules, 'mermaid'), join(root, 'not-isolated/mermaid'));
      await symlink(join(root, 'not-isolated/mermaid'), join(modules, 'mermaid'), 'junction');
    } else {
      const entry = join(modules, 'jsdom/lib/api.js');
      await rename(entry, join(root, 'not-isolated/api.js'));
      await symlink(join(root, 'not-isolated/api.js'), entry, 'file');
    }
    delete globalThis.__documentationIsolationProbe;
    const result = await checkDocumentation({ root, mermaidTools: tools });
    assert.equal(result.status, 'failed');
    assert.equal(globalThis.__documentationIsolationProbe, undefined);
    assert(result.failures.includes('Pinned isolated Mermaid tooling unavailable or invalid'));
  });
}
