import { extname, posix } from "node:path";

const JAVASCRIPT = new Set([".js", ".mjs", ".cjs"]);
const SAFE_BUILTINS = new Set([
  "node:assert", "node:assert/strict", "node:buffer", "node:crypto", "node:events",
  "node:fs", "node:fs/promises", "node:os", "node:path", "node:path/posix",
  "node:path/win32", "node:querystring", "node:stream", "node:stream/consumers",
  "node:stream/promises", "node:stream/web", "node:string_decoder", "node:timers",
  "node:timers/promises", "node:url", "node:util", "node:util/types", "node:zlib",
]);
const NETWORK_BUILTINS = new Set([
  "node:dgram", "node:dns", "node:dns/promises", "node:http", "node:http2",
  "node:https", "node:net", "node:tls",
]);
const STATIC_IMPORT = /\b(?:import|export)\s+(?:[^;\r\n]*?\s+from\s+)?(["'])([^"'\r\n]+)\1/g;
const REQUIRE = /\brequire\s*\(\s*(["'])([^"'\r\n]+)\1\s*\)/g;
const DYNAMIC_LOADER = /\bimport(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*\(|\brequire\b|\bcreateRequire\b|\b(?:eval|Function)\s*(?:\/\*[\s\S]*?\*\/\s*)?\(/;

function resolveRelative(from, specifier, paths) {
  if (specifier.includes("?") || specifier.includes("#") || specifier.includes("\\")) return false;
  const target = posix.normalize(posix.join(posix.dirname(from), specifier));
  if (target === ".." || target.startsWith("../") || target.startsWith("/")) return false;
  return [target, `${target}.js`, `${target}.mjs`, `${target}.cjs`, posix.join(target, "index.js"),
    posix.join(target, "index.mjs"), posix.join(target, "index.cjs")].some((candidate) => paths.has(candidate));
}

export function importPolicyIssues(files) {
  const paths = new Set(files.map(({ path }) => path.replaceAll("\\", "/")));
  const issues = [];
  for (const file of files) {
    const path = file.path.replaceAll("\\", "/");
    if ([".node", ".wasm"].includes(extname(path))) issues.push({ path, reason: "native and WebAssembly modules are not allowed" });
    if (!JAVASCRIPT.has(extname(path))) continue;
    if (DYNAMIC_LOADER.test(file.content)) issues.push({ path, reason: "dynamic code loaders are not allowed" });
    for (const pattern of [STATIC_IMPORT, REQUIRE]) {
      pattern.lastIndex = 0;
      for (let match; (match = pattern.exec(file.content));) {
        const specifier = match[2];
        if (NETWORK_BUILTINS.has(specifier)) continue;
        if (specifier.startsWith("node:")) {
          if (!SAFE_BUILTINS.has(specifier)) issues.push({ path, reason: `Node builtin is outside the MVP allowlist: ${specifier}` });
          continue;
        }
        if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
          issues.push({ path, reason: `bare or absolute import is not allowed: ${specifier}` });
        } else if (!resolveRelative(path, specifier, paths)) {
          issues.push({ path, reason: `relative import escapes or is missing: ${specifier}` });
        }
      }
    }
  }
  return issues;
}

export function runtimeEgressIssues(files) {
  const issues = [];
  for (const file of files) {
    const path = file.path.replaceAll("\\", "/");
    if (!JAVASCRIPT.has(extname(path))) continue;
    for (const pattern of [STATIC_IMPORT, REQUIRE]) {
      pattern.lastIndex = 0;
      for (let match; (match = pattern.exec(file.content));) {
        if (NETWORK_BUILTINS.has(match[2])) issues.push({ path, reason: `runtime network builtin is not allowed: ${match[2]}` });
      }
    }
    if (/\b(?:fetch|WebSocket|EventSource)\b/.test(file.content)) issues.push({ path, reason: "runtime network globals are not allowed" });
    if (/\bprocess\s*(?:\.\s*(?:binding|_linkedBinding|getBuiltinModule)|\[)/.test(file.content)) {
      issues.push({ path, reason: "process runtime bindings are not allowed" });
    }
  }
  return issues;
}

export function assertImportPolicy(files) {
  const issue = importPolicyIssues(files)[0];
  if (issue) throw new Error(`Artifact import policy rejected ${issue.path}: ${issue.reason}`);
}
