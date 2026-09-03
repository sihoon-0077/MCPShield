import { extname, posix } from "node:path";

const JAVASCRIPT = new Set([".js", ".mjs", ".cjs"]);
const STATIC_IMPORT = /\b(?:import|export)\s+(?:[^;\r\n]*?\s+from\s+)?(["'])([^"'\r\n]+)\1/g;
const REQUIRE = /\brequire\s*\(\s*(["'])([^"'\r\n]+)\1\s*\)/g;
const DYNAMIC_LOADER = /\bimport\s*\(|\bcreateRequire\b|\b(?:eval|Function)\s*\(/;

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
    if (!JAVASCRIPT.has(extname(path))) continue;
    if (DYNAMIC_LOADER.test(file.content)) issues.push({ path, reason: "dynamic code loaders are not allowed" });
    for (const pattern of [STATIC_IMPORT, REQUIRE]) {
      pattern.lastIndex = 0;
      for (let match; (match = pattern.exec(file.content));) {
        const specifier = match[2];
        if (specifier.startsWith("node:")) continue;
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

export function assertImportPolicy(files) {
  const issue = importPolicyIssues(files)[0];
  if (issue) throw new Error(`Artifact import policy rejected ${issue.path}: ${issue.reason}`);
}
