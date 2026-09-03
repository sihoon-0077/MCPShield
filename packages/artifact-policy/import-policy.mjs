import { extname, posix } from "node:path";

const JAVASCRIPT = new Set([".mjs"]);
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

function maskNonCode(source) {
  const chars = source.split("");
  let state = "CODE";
  for (let index = 0; index < chars.length; index += 1) {
    const current = chars[index];
    const next = chars[index + 1];
    if (state === "CODE" && current === "/" && next === "/") { chars[index] = chars[index + 1] = " "; state = "LINE_COMMENT"; index += 1; continue; }
    if (state === "CODE" && current === "/" && next === "*") { chars[index] = chars[index + 1] = " "; state = "BLOCK_COMMENT"; index += 1; continue; }
    if (state === "CODE" && ["'", '"', "`"].includes(current)) { state = current; chars[index] = " "; continue; }
    if (state === "LINE_COMMENT") { if (current === "\n" || current === "\r") state = "CODE"; else chars[index] = " "; continue; }
    if (state === "BLOCK_COMMENT") {
      if (current === "*" && next === "/") { chars[index] = chars[index + 1] = " "; state = "CODE"; index += 1; }
      else if (current !== "\n" && current !== "\r") chars[index] = " ";
      continue;
    }
    if (state !== "CODE") {
      if (current === "\\") { chars[index] = " "; if (index + 1 < chars.length) { chars[index + 1] = " "; index += 1; } continue; }
      if (current === state) state = "CODE";
      if (current !== "\n" && current !== "\r") chars[index] = " ";
    }
  }
  return chars.join("");
}

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
    if ([".js", ".cjs", ".node", ".wasm"].includes(extname(path))) issues.push({ path, reason: "only .mjs executable modules are allowed" });
    if (!JAVASCRIPT.has(extname(path))) continue;
    const code = maskNonCode(file.content);
    // Loader-shaped source is rejected raw, even in lexically ambiguous text. This is
    // intentionally fail-closed: a regex or template literal must never hide import().
    if (DYNAMIC_LOADER.test(file.content)) issues.push({ path, reason: "dynamic code loaders are not allowed" });
    if (/\bexport\b[^;]*\bfrom\b/.test(file.content)) issues.push({ path, reason: "re-export module loading is not allowed" });
    const importTokens = [...code.matchAll(/\bimport\b/g)].map((match) => match.index);
    STATIC_IMPORT.lastIndex = 0;
    const imports = [...file.content.matchAll(STATIC_IMPORT)];
    const recognizedImports = imports.map((match) => [match.index, match.index + match[0].length]);
    if (importTokens.some((index) => !recognizedImports.some(([start, end]) => index >= start && index < end))) {
      issues.push({ path, reason: "only single-line static import syntax is allowed" });
    }
    REQUIRE.lastIndex = 0;
    for (const matches of [imports, [...file.content.matchAll(REQUIRE)]]) {
      for (const match of matches) {
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
    const code = maskNonCode(file.content);
    if (DYNAMIC_LOADER.test(file.content)) issues.push({ path, reason: "dynamic code loaders are not allowed at runtime" });
    STATIC_IMPORT.lastIndex = 0;
    const imports = [...file.content.matchAll(STATIC_IMPORT)];
    REQUIRE.lastIndex = 0;
    const requires = [...file.content.matchAll(REQUIRE)];
    for (const matches of [imports, requires]) {
      for (const match of matches) {
        if (NETWORK_BUILTINS.has(match[2])) issues.push({ path, reason: `runtime network builtin is not allowed: ${match[2]}` });
      }
    }
    if (/\b(?:fetch|WebSocket|EventSource)\b/.test(code)) issues.push({ path, reason: "runtime network globals are not allowed" });
    if (/\bprocess\s*(?:\.\s*(?:binding|_linkedBinding|getBuiltinModule)|\[)/.test(code)) {
      issues.push({ path, reason: "process runtime bindings are not allowed" });
    }
  }
  return issues;
}

export function assertImportPolicy(files) {
  const issue = importPolicyIssues(files)[0];
  if (issue) throw new Error(`Artifact import policy rejected ${issue.path}: ${issue.reason}`);
}
