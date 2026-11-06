import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { posix } from 'node:path';
import ts from 'typescript';
// @ts-expect-error Pure shared serializer is JavaScript.
import { canonicalJson } from '../../services/scanner/src/canonical-json.mjs';
// @ts-expect-error Existing public API stays compatible.
import { canonicalJson as evidenceCanonical } from '../../services/scanner/src/evidence.mjs';

const root = new URL('../../', import.meta.url);
function imports(path: string) {
  const file = ts.createSourceFile(path, readFileSync(new URL(path, root), 'utf8'), ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  function visit(node: ts.Node) {
    const specifier = ts.isImportDeclaration(node) || ts.isExportDeclaration(node) ? node.moduleSpecifier
      : ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword ? node.arguments[0] : undefined;
    if (specifier && ts.isStringLiteral(specifier)) names.push(specifier.text);
    ts.forEachChild(node, visit);
  }
  visit(file); return names;
}
function assertCopiedClosure(copied: Set<string>) {
  for (const path of copied) for (const dependency of imports(path).filter(name => name.startsWith('.'))) {
    const target = posix.normalize(posix.join(posix.dirname(path), dependency));
    assert.ok(copied.has(target), `Dashboard Docker COPY missing ${target} imported by ${path}`);
  }
}
function copiedFiles() {
  const dockerfile = readFileSync(new URL('apps/dashboard/Dockerfile', root), 'utf8');
  // These COPY statements are explicit files, not directory globs or cross-stage copies.
  return new Set(dockerfile.split(/\r?\n/).filter(line => /^COPY (?:services\/|packages\/|apps\/gateway\/src\/|deployments\/|benchmarks\/)/.test(line))
    .flatMap(line => line.trim().split(/\s+/).slice(1, -1)));
}
function dashboardSources(dir = 'apps/dashboard'): string[] {
  return readdirSync(new URL(`${dir}/`, root), { withFileTypes: true }).flatMap(entry => {
    if (entry.isDirectory()) return ['node_modules', '.next', 'test'].includes(entry.name) ? [] : dashboardSources(`${dir}/${entry.name}`);
    return /\.(?:ts|tsx|mts|mjs)$/.test(entry.name) ? [`${dir}/${entry.name}`] : [];
  });
}
test('dashboard image copies every file outside apps/dashboard that the dashboard source imports', () => {
  const copied = copiedFiles(), sources = dashboardSources();
  assert.ok(sources.includes('apps/dashboard/lib/ledger-v3.ts'));
  for (const path of sources) for (const dependency of imports(path).filter(name => name.startsWith('.'))) {
    const target = posix.normalize(posix.join(posix.dirname(path), dependency));
    if (!target.startsWith('apps/dashboard/')) assert.ok(copied.has(target), `Dashboard Docker COPY missing ${target} imported by ${path}`);
  }
});
test('dashboard image copies the full explicit shared-module import closure', () => {
  const copied = copiedFiles();
  assert.ok(copied.size >= 8);
  assertCopiedClosure(copied);
  for (const omitted of ['scoped-policy.mjs', 'canonical-json.mjs']) {
    const incomplete = new Set(copied); incomplete.delete(`services/scanner/src/${omitted}`);
    assert.throws(() => assertCopiedClosure(incomplete), /Docker COPY missing/);
  }
});
test('client-side scoped policy validation has no Node or external runtime dependency', () => {
  const seen = new Set<string>();
  function visit(path: string) {
    if (seen.has(path)) return; seen.add(path);
    for (const dependency of imports(path)) {
      assert.ok(dependency.startsWith('.'), `Browser policy imports ${dependency}`);
      visit(posix.normalize(posix.join(posix.dirname(path), dependency)));
    }
  }
  visit('services/scanner/src/scoped-policy.mjs');
  assert.ok(seen.has('services/scanner/src/canonical-json.mjs'));
  assert.equal(canonicalJson, evidenceCanonical);
  assert.equal(canonicalJson({ z: [1, true, null], a: 'é' }), '{"a":"é","z":[1,true,null]}');
  assert.notEqual(canonicalJson('é'), canonicalJson('e\u0301'));
  for (const value of [undefined, NaN, Infinity, '\ud800', { '\udfff': 1 }]) assert.throws(() => canonicalJson(value));
});
