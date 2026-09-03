import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_FILES = 1_024;
const RELEASE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ENTRYPOINT_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);

export const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};

export function toolSurfaceHash(tools) {
  const normalized = [...tools].sort((left, right) => {
    const a = `${String(left.name)}\0${canonicalJson(left)}`;
    const b = `${String(right.name)}\0${canonicalJson(right)}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  return `0x${createHash("sha256").update(canonicalJson(normalized)).digest("hex")}`;
}

async function listSourceFiles(root, current = root) {
  const files = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error(`Artifact symlinks are not allowed: ${relative(root, path)}`);
    if (info.isDirectory()) files.push(...await listSourceFiles(root, path));
    else if (info.isFile()) files.push(path);
  }
  return files.sort((left, right) => {
    const a = relative(root, left).split(sep).join("/");
    const b = relative(root, right).split(sep).join("/");
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function validateManifest(value, availablePaths) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("manifest.json must contain an object");
  if (!RELEASE_NAME.test(value.name) || !SEMVER.test(value.version)) throw new TypeError("manifest name or version is not canonical");
  if (!Array.isArray(value.tools) || value.tools.length > 128) throw new TypeError("manifest tools must be a bounded array");
  const names = new Set();
  for (const tool of value.tools) {
    if (!tool || typeof tool !== "object" || Array.isArray(tool) || typeof tool.name !== "string" || !tool.name.trim()) throw new TypeError("each tool requires a name");
    if (names.has(tool.name)) throw new TypeError(`duplicate tool name: ${tool.name}`);
    names.add(tool.name);
  }
  if (typeof value.entrypoint !== "string" || !value.entrypoint || value.entrypoint.includes("\0") || isAbsolute(value.entrypoint)) throw new TypeError("manifest entrypoint is invalid");
  const normalized = value.entrypoint.replaceAll("\\", "/");
  if (normalized.startsWith("../") || normalized.includes("/../") || normalized === ".." || !availablePaths.has(normalized)) throw new TypeError("manifest entrypoint escapes or is missing from the artifact");
  if (!ENTRYPOINT_EXTENSIONS.has(extname(normalized))) throw new TypeError("manifest entrypoint must be JavaScript");
  return { ...value, entrypoint: normalized };
}

export async function createArtifactSnapshot(sourceDirectory) {
  if (typeof sourceDirectory !== "string" || !sourceDirectory) throw new TypeError("artifactDir is required");
  const sourceRoot = resolve(sourceDirectory);
  const sourceInfo = await lstat(sourceRoot);
  if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) throw new TypeError("artifactDir must be a real directory");
  const sourceFiles = await listSourceFiles(sourceRoot);
  if (!sourceFiles.length || sourceFiles.length > MAX_ARTIFACT_FILES) throw new Error("artifact file count is outside policy");

  const files = [];
  let totalBytes = 0;
  for (const sourcePath of sourceFiles) {
    const path = relative(sourceRoot, sourcePath).split(sep).join("/");
    const content = await readFile(sourcePath);
    totalBytes += content.byteLength;
    if (totalBytes > MAX_ARTIFACT_BYTES) throw new Error("artifact exceeds 16 MiB");
    files.push({ path, content });
  }
  const manifestFile = files.find(({ path }) => path === "manifest.json");
  if (!manifestFile) throw new TypeError("artifact manifest.json is required");
  const manifest = validateManifest(JSON.parse(manifestFile.content.toString("utf8")), new Set(files.map(({ path }) => path)));

  const digest = createHash("sha256");
  for (const file of files) digest.update(file.path).update("\0").update(file.content).update("\0");
  const snapshotRoot = await mkdtemp(join(tmpdir(), "mcpshield-artifact-"));
  try {
    for (const file of files) {
      const destination = join(snapshotRoot, ...file.path.split("/"));
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, file.content, { flag: "wx", mode: 0o400 });
      await chmod(destination, 0o400);
    }
    const entrypoint = join(snapshotRoot, ...manifest.entrypoint.split("/"));
    return {
      releaseId: `${manifest.name}@${manifest.version}`,
      artifactDigest: `sha256:${digest.digest("hex")}`,
      toolSurfaceHash: toolSurfaceHash(manifest.tools),
      tools: manifest.tools,
      entrypoint,
      root: snapshotRoot,
      cleanup: () => rm(snapshotRoot, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(snapshotRoot, { recursive: true, force: true });
    throw error;
  }
}
