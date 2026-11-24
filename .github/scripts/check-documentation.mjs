import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const workspace = fileURLToPath(new URL('../../', import.meta.url));
const require = createRequire(import.meta.url);
const markdown = require('prettier/plugins/markdown').parsers.markdown;
const policyPath = 'docs/authentication-and-recovery-policy.md';
const backlogPath = '.github/tasks/registration-single-contract-tasks.md';
const sections = [
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
const criteria = [
  ['Functional acceptance', 'F'],
  ['Security acceptance', 'S'],
  ['Unit tests', 'U'],
  ['Database/HTTP integration tests', 'I'],
  ['Concurrency/failure tests', 'X'],
  ['Browser/accessibility tests', 'B'],
  ['Documentation updates', 'D'],
  ['Completion criteria', 'C'],
];
const idPattern = /\bT\d{2}[A-Z]?\b/g;
const privatePath = /(?:^|[\/])\.(?:kilo|kilocode|opencode)(?:[\/]|$)/i;

export function parseMarkdown(source) {
  return markdown.parse(source);
}
function walk(node, visitor) {
  visitor(node);
  for (const child of node.children ?? []) walk(child, visitor);
}
function text(node) {
  return node.value ?? (node.children ?? []).map(text).join('');
}
function rows(node) {
  return node.children.map((row) => row.children.map(text));
}
function inside(root, target) {
  const relative = path.relative(root, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}
function confined(root, target) {
  const canonicalRoot = fs.realpathSync(root);
  const canonicalTarget = fs.realpathSync(target);
  return (
    inside(canonicalRoot, canonicalTarget) &&
    !privatePath.test(path.relative(canonicalRoot, canonicalTarget))
  );
}

export function headingAnchors(ast) {
  const anchors = new Set();
  const counts = new Map();
  const generated = new Set();
  walk(ast, (node) => {
    if (node.type === 'heading') {
      // Owned documentation uses GitHub-style Unicode headings, not generated HTML slugs.
      const base = text(node)
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '')
        .replace(/ /g, '-');
      let count = counts.get(base) ?? 0;
      let anchor = count ? `${base}-${count}` : base;
      while (generated.has(anchor)) {
        count++;
        anchor = `${base}-${count}`;
      }
      counts.set(base, count + 1);
      generated.add(anchor);
      anchors.add(anchor);
    }
    if (node.type === 'html')
      for (const match of node.value.matchAll(/\bid=["']([^"']+)["']/g)) anchors.add(match[1]);
  });
  return anchors;
}

function historical(ast, node, filename) {
  if (filename.startsWith('docs/history/') || filename === 'tasks.md') return true;
  return ast.children.some((heading, index) => {
    const dated =
      /20\d\d-\d\d-\d\d|(?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, 20\d{2}/.test(
        text(heading)
      );
    if (heading.type !== 'heading' || (!dated && !/^Preserved Historical/.test(text(heading))))
      return false;
    let end = Infinity;
    for (const next of ast.children.slice(index + 1)) {
      if (next.type === 'heading' && next.depth <= heading.depth) {
        end = next.position.start.line;
        break;
      }
    }
    return node.position.start.line > heading.position.start.line && node.position.start.line < end;
  });
}

export function validateLinks(filename, ast, documents, root, pendingOutput) {
  const errors = [];
  const counts = { links: 0, anchors: 0 };
  const definitions = new Map();
  walk(ast, (node) => {
    if (node.type === 'definition') definitions.set(node.identifier.toLowerCase(), node.url);
  });
  const fail = (node, message) =>
    errors.push(`${filename}:${node.position?.start.line ?? 1} ${message}`);
  walk(ast, (node) => {
    let url;
    if (node.type === 'link' || node.type === 'image') url = node.url;
    if (node.type === 'linkReference' || node.type === 'imageReference') {
      url = definitions.get(node.identifier.toLowerCase());
      if (!url) fail(node, 'Unresolved reference-style link');
    }
    if (!url) return;
    counts.links++;
    if (/^(?:https?:|mailto:|data:)/i.test(url)) return;
    if (/^[a-z][a-z\d+.-]*:/i.test(url)) {
      fail(node, 'Unsupported local-link protocol');
      return;
    }
    const [rawPath, rawAnchor] = url.split('#');
    let decoded;
    let anchor;
    try {
      decoded = decodeURIComponent(rawPath).split('?')[0];
      anchor = rawAnchor ? decodeURIComponent(rawAnchor) : '';
    } catch {
      fail(node, 'Invalid link encoding');
      return;
    }
    if (path.isAbsolute(decoded) || path.win32.isAbsolute(decoded)) {
      fail(node, 'Absolute local links are not portable');
      return;
    }
    const target = decoded
      ? path.resolve(root, path.dirname(filename), decoded)
      : path.resolve(root, filename);
    if (!inside(root, target) || privatePath.test(path.relative(root, target))) {
      fail(node, 'Link requires private or outside-checkout content');
      return;
    }
    // A new JSON report may describe the documents which link to that same report.
    if (
      !fs.existsSync(target) &&
      target === pendingOutput &&
      path.extname(target) === '.json' &&
      !anchor
    ) {
      if (!fs.existsSync(path.dirname(target)) || !confined(root, path.dirname(target)))
        fail(node, 'Report parent escapes shared checkout content');
      return;
    }
    if (!fs.existsSync(target)) {
      fail(node, 'Missing local link target');
      return;
    }
    if (!confined(root, target)) {
      fail(node, 'Link resolves outside shared checkout content');
      return;
    }
    if (anchor && target.endsWith('.md')) {
      counts.anchors++;
      const relative = path.relative(root, target).split(path.sep).join('/');
      const entry = documents.get(relative);
      if (!entry || !headingAnchors(entry.ast).has(anchor))
        fail(node, 'Missing local Markdown anchor');
    }
  });
  return { errors, counts };
}

export function validateBacklog(ast) {
  const errors = [];
  const ids = new Set();
  const primaryIds = new Set();
  const expected = new Set();
  const declared = new Set();
  const criterionIds = new Set();
  const records = new Map();
  const waves = new Map();
  let criterionCount = 0;
  walk(ast, (node) => {
    if (node.type !== 'table') return;
    const table = rows(node);
    if (table[0]?.[0] === 'Primary ID')
      for (const row of table.slice(1)) {
        if (!/^T\d{2}$/.test(row[0])) {
          errors.push('Malformed primary task inventory');
          continue;
        }
        if (primaryIds.has(row[0])) errors.push(`Duplicate primary inventory ID ${row[0]}`);
        primaryIds.add(row[0]);
        ids.add(row[0]);
        for (const match of (row[1] ?? '').matchAll(idPattern)) {
          if (declared.has(match[0]))
            errors.push(`Duplicate executable inventory membership ${match[0]}`);
          if (!match[0].startsWith(row[0]))
            errors.push(`Executable assigned to the wrong primary ${match[0]}`);
          declared.add(match[0]);
          expected.add(match[0]);
          ids.add(match[0]);
        }
      }
    if (table[0]?.[0] === 'Wave')
      for (const [wave, values] of table.slice(1)) {
        if (!/^\d+$/.test(wave)) errors.push('Invalid topological wave');
        for (const match of values.matchAll(idPattern)) {
          if (waves.has(match[0])) errors.push(`Duplicate wave task ${match[0]}`);
          waves.set(match[0], Number(wave));
        }
      }
    if (table[0]?.[0] !== 'Section' || table[0]?.[1] !== 'Requirement') return;
    const fields = new Map(table.slice(1));
    const id = fields.get('ID/title')?.match(/^T\d{2}[A-Z]?\b/)?.[0];
    if (!id) {
      errors.push('Malformed executable ID/title');
      return;
    }
    if (records.has(id)) errors.push(`Duplicate executable record ${id}`);
    records.set(id, fields);
    if (table.length !== 16 || fields.size !== 15)
      errors.push(`${id} must contain exactly 15 sections`);
    for (const section of sections)
      if (!fields.get(section)?.trim()) errors.push(`${id} missing ${section}`);
    for (const [section, letter] of criteria) {
      if (!fields.get(section)?.startsWith(`${id}-${letter}01:`))
        errors.push(`${id} missing stable ${section} criterion`);
      for (const match of (fields.get(section) ?? '').matchAll(/\b(T\d{2}[A-Z]?)-([A-Z])(\d+):/g)) {
        const criterion = match[0].slice(0, -1);
        if (
          match[1] !== id ||
          match[2] !== letter ||
          !/^\d{2}$/.test(match[3]) ||
          Number(match[3]) < 1
        )
          errors.push(`Wrong-task or malformed criterion ${criterion}`);
        if (criterionIds.has(criterion)) errors.push(`Duplicate criterion identifier ${criterion}`);
        criterionIds.add(criterion);
        criterionCount++;
      }
    }
  });
  for (let number = 1; number <= 42; number++)
    if (!ids.has(`T${String(number).padStart(2, '0')}`))
      errors.push(`Missing primary T${String(number).padStart(2, '0')}`);
  if (expected.has('T12') || records.has('T12')) errors.push('T12 must remain excluded');
  for (const id of expected)
    if (!records.has(id)) errors.push(`Inventory task missing executable record ${id}`);
  for (const id of records.keys())
    if (!expected.has(id)) errors.push(`Executable not declared in inventory ${id}`);
  for (const id of waves.keys())
    if (!records.has(id)) errors.push(`Non-executable wave task ${id}`);
  const edges = new Map();
  let dependencyCount = 0;
  for (const [id, fields] of records) {
    const dependencies = [...(fields.get('Dependencies') ?? '').matchAll(idPattern)].map(
      (match) => match[0]
    );
    edges.set(id, dependencies);
    dependencyCount += dependencies.length;
    if (new Set(dependencies).size !== dependencies.length)
      errors.push(`Duplicate dependency in ${id}`);
    if (!waves.has(id)) errors.push(`Missing wave for ${id}`);
    for (const dependency of dependencies) {
      if (!records.has(dependency))
        errors.push(`${id} depends on missing, aggregate or excluded ${dependency}`);
      if (waves.get(dependency) >= waves.get(id))
        errors.push(`${id} dependency is not in an earlier wave`);
    }
  }
  const visited = new Set();
  const visiting = new Set();
  function visit(id) {
    if (visiting.has(id)) {
      errors.push(`Dependency cycle at ${id}`);
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of edges.get(id) ?? []) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of records.keys()) visit(id);
  return {
    errors,
    ids,
    counts: {
      executableRecords: records.size,
      taskSections: [...records.values()].reduce((sum, fields) => sum + fields.size, 0),
      criteria: criterionCount,
      dependencyEdges: dependencyCount,
    },
  };
}

function markdownFiles(root, directory) {
  if (!confined(root, directory))
    throw new Error('Document directory is outside shared checkout content');
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory()
        ? markdownFiles(root, path.join(directory, entry.name))
        : entry.isFile() && entry.name.endsWith('.md')
          ? [path.join(directory, entry.name)]
          : []
    );
}

export async function checkDocumentation({
  root = workspace,
  referencesOnly = false,
  mermaidTools,
  output,
} = {}) {
  const documents = new Map();
  const files = [
    'README.md',
    'tasks.md',
    backlogPath,
    ...markdownFiles(root, path.join(root, 'docs')).map((file) =>
      path.relative(root, file).split(path.sep).join('/')
    ),
  ].sort();
  for (const filename of files) {
    if (!confined(root, path.join(root, filename)))
      throw new Error('Document file is outside shared checkout content');
    const source = fs.readFileSync(path.join(root, filename), 'utf8');
    documents.set(filename, { source, ast: parseMarkdown(source) });
  }
  const failures = [];
  const counts = {
    documents: documents.size,
    links: 0,
    anchors: 0,
    sourceRanges: 0,
    diagrams: 0,
    invariantReferences: 0,
    taskReferences: 0,
    commands: 0,
    historicalCommandBlocks: 0,
  };
  const backlog = validateBacklog(documents.get(backlogPath).ast);
  failures.push(...backlog.errors);
  Object.assign(counts, backlog.counts);
  const invariants = new Set();
  walk(documents.get(policyPath).ast, (node) => {
    if (node.type === 'table')
      for (const row of rows(node)) if (/^SEC\d{2}$/.test(row[0])) invariants.add(row[0]);
  });
  for (let number = 1; number <= 16; number++)
    if (!invariants.has(`SEC${String(number).padStart(2, '0')}`))
      failures.push('Missing normative invariant definition');
  const diagrams = [];
  const projects = new Map();
  function targetExists(project, target) {
    if (!projects.has(project)) {
      try {
        const nxDirectory = path.join(root, 'node_modules/nx');
        const nx = JSON.parse(fs.readFileSync(path.join(nxDirectory, 'package.json'), 'utf8'));
        const result = execFileSync(
          process.execPath,
          [path.resolve(nxDirectory, nx.bin.nx), 'show', 'project', project, '--json'],
          {
            cwd: root,
            encoding: 'utf8',
            timeout: 120_000,
            env: { ...process.env, NX_DAEMON: 'false' },
            stdio: ['ignore', 'pipe', 'pipe'],
            maxBuffer: 16 * 1024 * 1024,
          }
        );
        projects.set(project, new Set(Object.keys(JSON.parse(result).targets)));
      } catch {
        projects.set(project, new Set());
      }
    }
    return projects.get(project).has(target);
  }
  for (const [filename, entry] of documents) {
    const links = validateLinks(filename, entry.ast, documents, root, output);
    failures.push(...links.errors);
    counts.links += links.counts.links;
    counts.anchors += links.counts.anchors;
    walk(entry.ast, (node) => {
      const fail = (message) =>
        failures.push(`${filename}:${node.position?.start.line ?? 1} ${message}`);
      if (node.type === 'code' && node.lang === 'mermaid') diagrams.push({ filename, node });
      if (historical(entry.ast, node, filename)) {
        if (node.value?.includes('npm exec -- nx')) counts.historicalCommandBlocks++;
        return;
      }
      const value = node.value ?? '';
      if (/\.kilo(?:code)?\/|\/tmp\/kilo\//.test(value))
        fail('Active guidance depends on local agent or temporary state');
      if (node.type !== 'code') {
        for (const match of value.matchAll(/\bSEC\d{2}\b/g)) {
          counts.invariantReferences++;
          if (!invariants.has(match[0])) fail('Unknown security invariant');
        }
        for (const match of value.matchAll(idPattern)) {
          counts.taskReferences++;
          if (!backlog.ids.has(match[0])) fail('Unknown task reference');
        }
      }
      if (node.type !== 'inlineCode' && node.type !== 'code') return;
      for (const match of value.matchAll(
        /((?:apps\/identity-api\/)?(?:internal|db)\/[\w/.-]+\.(?:go|sql)):(\d[\d,\-]*)/g
      )) {
        counts.sourceRanges++;
        const sourcePath = path.join(
          root,
          match[1].startsWith('apps/') ? match[1] : `apps/identity-api/${match[1]}`
        );
        if (!fs.existsSync(sourcePath)) {
          fail('Missing current cited source');
          continue;
        }
        if (!confined(root, sourcePath)) {
          fail('Current cited source is outside shared checkout content');
          continue;
        }
        const length = fs.readFileSync(sourcePath, 'utf8').split('\n').length;
        for (const group of match[2].split(',')) {
          const bounds = group.split('-').map(Number);
          if (
            bounds.some((number) => number < 1 || number > length) ||
            (bounds.length === 2 && bounds[1] < bounds[0])
          )
            fail('Current source citation outside line range');
        }
      }
      for (const match of value.matchAll(/npm exec -- nx run ([\w-]+):([\w-]+)/g)) {
        counts.commands++;
        if (!targetExists(match[1], match[2])) fail('Unresolved current Nx target');
      }
      for (const match of value.matchAll(/npm exec -- nx run-many ([^\n]+)/g)) {
        const target = match[1].match(/(?:^|\s)(?:-t|--targets)(?:=|\s+)([\w,-]+)/)?.[1];
        const project = match[1].match(/(?:^|\s)(?:-p|--projects)(?:=|\s+)([\w,-]+)/)?.[1];
        if (!target || !project) continue;
        for (const name of project.split(','))
          for (const task of target.split(',')) {
            counts.commands++;
            if (!targetExists(name, task)) fail('Unresolved current Nx run-many target');
          }
      }
    });
  }
  for (const filename of documents.keys())
    if (filename.startsWith('docs/') && !documents.get('README.md').source.includes(filename))
      failures.push(`Document absent from root index: ${filename}`);
  counts.diagrams = diagrams.length;
  let diagramStatus = {
    status: 'not-run',
    reason: 'Explicit references-only mode; no diagram pass claimed',
  };
  if (!referencesOnly) {
    diagramStatus = {
      status: 'failed',
      reason: 'Full validation requires explicit pinned isolated Mermaid tools',
    };
    try {
      const canonicalRoot = fs.realpathSync(root);
      const tools = mermaidTools && fs.realpathSync(mermaidTools);
      if (!tools || inside(canonicalRoot, tools)) throw new Error('Invalid isolated directory');
      const isolated = (candidate) => {
        const canonical = fs.realpathSync(candidate);
        if (!inside(tools, canonical) || inside(canonicalRoot, canonical))
          throw new Error('Diagram package escapes isolation');
        return canonical;
      };
      const modules = isolated(path.join(tools, 'node_modules'));
      const mermaidDirectory = isolated(path.join(modules, 'mermaid'));
      const jsdomDirectory = isolated(path.join(modules, 'jsdom'));
      const mermaidVersion = JSON.parse(
        fs.readFileSync(isolated(path.join(mermaidDirectory, 'package.json')), 'utf8')
      ).version;
      const jsdomVersion = JSON.parse(
        fs.readFileSync(isolated(path.join(jsdomDirectory, 'package.json')), 'utf8')
      ).version;
      if (mermaidVersion !== '11.17.2' || jsdomVersion !== '27.4.0')
        throw new Error('Unexpected diagram tool version');
      const jsdomEntry = isolated(path.join(jsdomDirectory, 'lib/api.js'));
      const mermaidEntry = isolated(path.join(mermaidDirectory, 'dist/mermaid.core.mjs'));
      const { JSDOM } = await import(pathToFileURL(jsdomEntry).href);
      const dom = new JSDOM('<!doctype html><html><body></body></html>');
      const previous = {
        window: globalThis.window,
        document: globalThis.document,
        DOMParser: globalThis.DOMParser,
      };
      try {
        globalThis.window = dom.window;
        globalThis.document = dom.window.document;
        globalThis.DOMParser = dom.window.DOMParser;
        const { default: mermaid } = await import(pathToFileURL(mermaidEntry).href);
        mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
        let valid = true;
        for (const { filename, node } of diagrams) {
          try {
            await mermaid.parse(node.value);
          } catch {
            valid = false;
            failures.push(`${filename}:${node.position.start.line} Invalid Mermaid syntax`);
          }
        }
        diagramStatus = {
          status: valid ? 'passed' : 'failed',
          mermaid: mermaidVersion,
          jsdom: jsdomVersion,
        };
      } finally {
        Object.assign(globalThis, previous);
        dom.window.close();
      }
    } catch {
      failures.push('Pinned isolated Mermaid tooling unavailable or invalid');
    }
  }
  let sourceCommit = null;
  try {
    sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    /* Source archive has no Git metadata; do not invent a commit identity. */
  }
  const hash = createHash('sha256');
  for (const [filename, entry] of documents)
    hash.update(filename).update('\0').update(entry.source).update('\0');
  return {
    schema: 1,
    scope: 'documentation',
    sourceCommit,
    node: process.version,
    prettier: require('prettier/package.json').version,
    counts,
    diagrams: diagramStatus,
    documentationSHA256: hash.digest('hex'),
    checkerSHA256: createHash('sha256')
      .update(fs.readFileSync(fileURLToPath(import.meta.url)))
      .digest('hex'),
    testsSHA256: createHash('sha256')
      .update(fs.readFileSync(new URL('./check-documentation.test.mjs', import.meta.url)))
      .digest('hex'),
    documents: [...documents.keys()],
    failures,
    status: failures.length ? 'failed' : 'passed',
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {};
    for (let index = 2; index < process.argv.length; index++) {
      const argument = process.argv[index];
      if (argument === '--references-only') options.referencesOnly = true;
      else if (argument === '--mermaid-tools' || argument === '--output') {
        const value = process.argv[++index];
        if (!value || value.startsWith('--')) throw new Error('Missing argument');
        options[argument === '--output' ? 'output' : 'mermaidTools'] = path.resolve(value);
      } else throw new Error('Unknown argument');
    }
    if (options.referencesOnly && options.mermaidTools)
      throw new Error('Conflicting validation modes');
    const report = await checkDocumentation(options);
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    if (options.output && !report.failures.length) {
      if (path.extname(options.output) !== '.json') throw new Error('Evidence output must be JSON');
      if (inside(workspace, options.output) && !confined(workspace, path.dirname(options.output)))
        throw new Error('Evidence output parent is not shared checkout content');
      fs.writeFileSync(options.output, serialized, { flag: 'wx' });
    }
    console.log(serialized.trimEnd());
    if (report.failures.length) process.exitCode = 1;
  } catch {
    console.error(
      'Documentation check could not complete: verify arguments, checkout, dependencies and new JSON output path'
    );
    process.exitCode = 1;
  }
}
