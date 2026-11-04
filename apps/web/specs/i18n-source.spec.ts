/** @jest-environment node */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';
import en from '../messages/en';
import fa from '../messages/fa-IR';

// Application-owned presentation is catalogued. Protocol values, user input,
// backend evidence and developer diagnostics remain exact. This guard examines
// presentation sinks instead of treating every English identifier as prose.
function uncatalogued(source: ts.SourceFile): string[] {
  const failures: string[] = [];
  const humanText = (value: string) => /[A-Za-z\u0600-\u06ff]/u.test(value);
  const prose = (value: string) =>
    /[A-Za-z\u0600-\u06ff]{2,}\s+[A-Za-z\u0600-\u06ff]{2,}/u.test(value);
  function presentationExpression(node: ts.Node) {
    return (
      ts.isJsxExpression(node) &&
      (!ts.isJsxAttribute(node.parent) ||
        /^(aria-label|title|description|placeholder|alt|label|caption)$/.test(
          node.parent.name.getText(source)
        ))
    );
  }
  function report(node: ts.Node, value: string) {
    failures.push(
      `${source.fileName}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}: ${value.trim()}`
    );
  }
  function inspect(node: ts.Node) {
    if (ts.isJsxText(node) && humanText(node.text)) report(node, node.text);
    if (
      ts.isJsxAttribute(node) &&
      /^(aria-label|title|description|placeholder|alt|label|caption)$/.test(
        node.name.getText(source)
      ) &&
      node.initializer &&
      ts.isStringLiteral(node.initializer) &&
      humanText(node.initializer.text)
    )
      report(node, node.initializer.text);
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      prose(node.text)
    ) {
      const parent = node.parent;
      if (presentationExpression(parent)) report(node, node.text);
      if (
        ts.isPropertyAssignment(parent) &&
        /^(message|error|title|description|caption|placeholder)$/.test(parent.name.getText(source))
      )
        report(node, node.text);
      if (
        ts.isCallExpression(parent) &&
        /^(setStatus|setError|setNotice|setCodeError|setInputError)$/.test(
          parent.expression.getText(source)
        )
      )
        report(node, node.text);
    }
    if (ts.isTemplateExpression(node)) {
      const text = [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(
        ' '
      );
      if (
        prose(text) &&
        (presentationExpression(node.parent) ||
          (ts.isCallExpression(node.parent) &&
            /^(setStatus|setError|setNotice)$/.test(node.parent.expression.getText(source))))
      )
        report(node, text);
    }
    if (
      ts.isCallExpression(node) &&
      /^(setStatus|setError|setNotice|setCodeError|setInputError)$/.test(
        node.expression.getText(source)
      )
    ) {
      for (const argument of node.arguments) {
        if (
          ts.isCallExpression(argument) &&
          /^(t|message)$/.test(argument.expression.getText(source))
        )
          report(argument, 'Translated feedback must be resolved at render time');
      }
    }
    ts.forEachChild(node, inspect);
  }
  inspect(source);
  return failures;
}

it('keeps owned JSX, accessible labels, metadata, validation and feedback prose in catalogs', () => {
  const root = join(process.cwd(), 'app');
  const violations = readdirSync(root, { recursive: true })
    .filter(
      (file): file is string =>
        typeof file === 'string' && /\.(ts|tsx)$/.test(file) && !/\.(spec|test)\./.test(file)
    )
    .flatMap((file) => {
      const path = join(root, file);
      return uncatalogued(
        ts.createSourceFile(
          relative(process.cwd(), path),
          readFileSync(path, 'utf8'),
          ts.ScriptTarget.Latest,
          true,
          file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
        )
      );
    });
  expect(violations).toEqual([]);
});

it('detects newly introduced presentation sinks without broad file exemptions', () => {
  const fixture = ts.createSourceFile(
    'fixture.tsx',
    `
    const metadata = { title: 'New page title' };
    setStatus('Please try again');
    const field = { message: 'Enter your name' };
    const ui = <button aria-label="New action">Save now</button>;
  `,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX
  );
  expect(uncatalogued(fixture)).toHaveLength(5);
});

function leaves(value: object, prefix = ''): Record<string, string> {
  return Object.fromEntries(
    Object.entries(value).flatMap(([key, entry]) => {
      const name = prefix ? `${prefix}.${key}` : key;
      return typeof entry === 'string' ? [[name, entry]] : Object.entries(leaves(entry, name));
    })
  );
}

it('allows identical Persian leaves only for reviewed technical terms', () => {
  const original = leaves(en);
  const translated = leaves(fa);
  const identical = Object.entries(original)
    .filter(([key, text]) => translated[key] === text)
    .map(([key]) => key)
    .sort();
  // Add an exact key here only after reviewing the protocol/brand exception.
  expect(identical).toEqual(['preferences.english', 'preferences.persian']);
});
