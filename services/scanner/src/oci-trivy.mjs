import { randomUUID } from 'node:crypto';
import { chmod, lstat, mkdtemp, mkdir, open, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { copyFixtureSnapshot, removeFixtureSnapshot, TRIVY_DATABASE_BUDGET_PROFILE } from './snapshot.mjs';
import { artifactDigest } from './scanner.mjs';
import { canonicalJson } from './evidence.mjs';
import { ociHash, OCI_RUNTIME_LIMITS } from '../../resolver/src/oci-runtime-descriptor.mjs';
import { runRuntimeDocker } from '../../resolver/src/npm-closure.mjs';
import { validateRuntimePlatform } from '../../resolver/src/runtime-descriptor.mjs';

const sha = /^sha256:[a-f0-9]{64}$/;
const jsonLimit = 16 * 1024 * 1024;
const databaseAgeMs = 24 * 60 * 60 * 1000;

export function checkedTrivyDatabaseMetadata(metadata, now = Date.now()) {
  const updated = Date.parse(metadata?.UpdatedAt), next = Date.parse(metadata?.NextUpdate);
  if (metadata?.Version !== 2 || !Number.isFinite(updated) || !Number.isFinite(next) || next < updated ||
    updated > now + 5 * 60 * 1000 || now - updated > databaseAgeMs) throw Error('OCI_TRIVY_DATABASE_STALE_OR_INVALID');
  return { schemaVersion: metadata.Version, updatedAt: new Date(updated).toISOString(), nextUpdate: new Date(next).toISOString(), maxAgeHours: 24 };
}

// Caller-local trusted DB only; this function never downloads or repairs it.
// The optional target is an exclusively owned private job directory.
export async function readTrivyDatabaseIdentity({ databaseDir, snapshotDir, signal }) {
  signal?.throwIfAborted();
  if (typeof databaseDir !== 'string' || !isAbsolute(databaseDir) ||
    (await readdir(databaseDir)).sort().join() !== 'metadata.json,trivy.db') throw Error('OCI_TRIVY_DATABASE_LAYOUT_INVALID');
  if ((await lstat(join(databaseDir, 'metadata.json'))).size > 64 * 1024) throw Error('OCI_TRIVY_DATABASE_METADATA_LIMIT');
  let workspace;
  if (!snapshotDir) workspace = await mkdtemp(join(tmpdir(), 'mcpshield-trivy-db-'));
  const root = snapshotDir ?? join(workspace, 'db');
  try {
    const copied = await copyFixtureSnapshot(databaseDir, root, { profile: TRIVY_DATABASE_BUDGET_PROFILE, signal });
    const handle = await open(join(root, 'metadata.json'), 'r');
    let raw;
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size > 64 * 1024) throw Error('OCI_TRIVY_DATABASE_METADATA_LIMIT');
      const buffer = Buffer.alloc(64 * 1024 + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead !== before.size || (await handle.stat()).size !== before.size) throw Error('OCI_TRIVY_DATABASE_METADATA_LIMIT');
      raw = buffer.subarray(0, bytesRead);
    } finally { await handle.close(); }
    signal?.throwIfAborted();
    const metadata = checkedTrivyDatabaseMetadata(JSON.parse(raw));
    const databaseDigest = await artifactDigest(root, { profile: TRIVY_DATABASE_BUDGET_PROFILE, signal });
    return { databaseDigest, bytes: copied.bytes, ...metadata, ...(snapshotDir ? { snapshotDir: root } : {}) };
  } finally { if (workspace) await removeFixtureSnapshot(workspace); }
}

export function assessTrivyDocuments(report, sbom, imageDigest) {
  if (report?.SchemaVersion !== 2 || report.ArtifactType !== 'container_image' || report.Metadata?.ImageID !== imageDigest ||
    !Array.isArray(report.Results) || report.Results.length > 1024 || sbom?.bomFormat !== 'CycloneDX' ||
    !['1.4', '1.5', '1.6'].includes(sbom.specVersion) || !Array.isArray(sbom.components) || sbom.components.length > 50_000) throw Error('OCI_TRIVY_REPORT_IDENTITY_INVALID');
  if (report.Results.some((result) => !result || typeof result !== 'object' ||
    result.Packages !== undefined && !Array.isArray(result.Packages) || result.Vulnerabilities !== undefined && !Array.isArray(result.Vulnerabilities)) ||
    sbom.components.some((item) => !item || typeof item.name !== 'string' || item.version !== undefined && typeof item.version !== 'string' ||
      item.group !== undefined && typeof item.group !== 'string')) throw Error('OCI_TRIVY_REPORT_INVALID');
  const packages = report.Results.flatMap((result) => result.Packages ?? []);
  const vulnerabilities = report.Results.flatMap((result) => result.Vulnerabilities ?? []);
  if (packages.length > 50_000 || vulnerabilities.length > 50_000 || packages.some((pkg) =>
    typeof pkg.Name !== 'string' || typeof pkg.Version !== 'string') || vulnerabilities.some((item) =>
    typeof item.VulnerabilityID !== 'string' || !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(item.Severity))) throw Error('OCI_TRIVY_REPORT_INVALID');
  const components = new Set(sbom.components.map((component) => `${component.group ? component.group + '/' : ''}${component.name}\0${component.version}`));
  const packageListComplete = packages.length > 0 && packages.every((pkg) => components.has(`${pkg.Name}\0${pkg.Version}`));
  const highCriticalCount = vulnerabilities.filter(({ Severity }) => ['HIGH', 'CRITICAL'].includes(Severity)).length;
  const issues = [];
  if (!packageListComplete) issues.push('OCI_TRIVY_PACKAGE_COVERAGE_INCOMPLETE');
  if (report.Metadata.OS?.EOSL === true || report.Metadata.OS?.Eosl === true) issues.push('OCI_TRIVY_OS_END_OF_LIFE');
  if (highCriticalCount) issues.push('OCI_HIGH_CRITICAL_VULNERABILITIES');
  return { imageDigest, status: issues.length ? 'INCONCLUSIVE' : 'COMPLETE', packages: packages.length, components: sbom.components.length,
    highCriticalCount, packageListComplete, coverage: 'TRIVY_DETECTED_PACKAGES_NOT_ALL_SOURCE_SEMANTICS',
    reportDigest: ociHash(canonicalJson(report)), sbomDigest: ociHash(canonicalJson(sbom)), issues };
}

// Only schema shapes/counts and numeric versions; no package names, paths,
// candidate source, raw CLI output or exception strings enter diagnostics.
export function trivyContractDiagnostics(report, sbom, imageDigest) {
  const shape = (value) => Array.isArray(value) ? 'ARRAY' : value === undefined ? 'MISSING' : value === null ? 'NULL' : 'OTHER';
  return { reportSchemaVersion: Number.isSafeInteger(report?.SchemaVersion) ? report.SchemaVersion : null,
    reportArtifactType: report?.ArtifactType === 'container_image' ? 'container_image' : 'OTHER',
    reportImageIdMatches: report?.Metadata?.ImageID === imageDigest,
    reportResultsShape: shape(report?.Results), reportResultsCount: Array.isArray(report?.Results) ? report.Results.length : null,
    sbomFormat: sbom?.bomFormat === 'CycloneDX' ? 'CycloneDX' : 'OTHER',
    sbomSpecVersion: typeof sbom?.specVersion === 'string' && /^[0-9]{1,3}\.[0-9]{1,3}$/.test(sbom.specVersion) ? sbom.specVersion : 'OTHER',
    sbomComponentsShape: shape(sbom?.components), sbomComponentsCount: Array.isArray(sbom?.components) ? sbom.components.length : null };
}

// Images, tool CID and DB path/hash come only from server/operator configuration.
// The scanner container sees native save bytes, not a Docker socket or secrets.
export async function scanOciWithTrivy({ imageDigest, baseImageDigest, platform, trust, timeoutMs = 180_000 }) {
  if (![imageDigest, baseImageDigest, trust?.trivyImageDigest, trust?.databaseDigest].every((value) => sha.test(value)) ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 180_000) throw Error('OCI_TRIVY_TRUST_REQUIRED');
  validateRuntimePlatform(platform);
  if (process.platform !== 'linux') return { status: 'NOT_RUN', issues: ['OCI_LINUX_DOCKER_REQUIRED'], privateEvidence: null };
  const started = Date.now(), deadline = started + timeoutMs, signal = AbortSignal.timeout(timeoutMs);
  const remaining = () => { signal.throwIfAborted(); if (Date.now() >= deadline) throw Error('OCI_TRIVY_TOTAL_TIMEOUT'); return deadline - Date.now(); };
  const run = (args, size = jsonLimit) => runRuntimeDocker(args, remaining(), size);
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-trivy-review-')), input = join(workspace, 'input'), db = join(workspace, 'db');
  const containers = [];
  let stage = 'DATABASE', contract = null, toolVersion = null;
  try {
    const database = await readTrivyDatabaseIdentity({ databaseDir: trust.databaseDir, snapshotDir: db, signal });
    if (database.databaseDigest !== trust.databaseDigest) throw Error('OCI_TRIVY_DATABASE_IDENTITY_MISMATCH');
    for (const file of ['metadata.json', 'trivy.db']) await chmod(join(db, file), 0o444);
    await chmod(db, 0o555);
    await mkdir(input, { mode: 0o755 });
    await writeFile(join(input, 'trivy.yaml'), '{}', { flag: 'wx', mode: 0o444 });
    await writeFile(join(input, 'empty.ignore'), '', { flag: 'wx', mode: 0o444 });
    stage = 'TOOL_IDENTITY';
    const tool = JSON.parse(await run(['image', 'inspect', trust.trivyImageDigest, '--format', '{{json .}}'], 128 * 1024));
    if (tool.Id !== trust.trivyImageDigest || tool.Os !== platform.os || tool.Architecture !== platform.architecture ||
      canonicalJson(tool.Config?.Entrypoint) !== '["trivy"]') throw Error('OCI_TRIVY_TOOL_IDENTITY_MISMATCH');
    const invoke = async (args) => {
      const container = `mcpshield-trivy-${randomUUID()}`; containers.push(container);
      return run(['run', '--pull=never', '--name', container, '--network=none', '--read-only', '--user=1000:1000',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=1536m', '--cpus=1', '--pids-limit=64', '--workdir=/tmp',
        '--tmpfs=/tmp:rw,noexec,nosuid,size=640m', '--tmpfs=/cache:rw,noexec,nosuid,size=64m',
        '--mount', `type=bind,source=${db},target=/cache/db,readonly`, '--mount', `type=bind,source=${input},target=/input,readonly`,
        '--env=HOME=/tmp', '--env=PATH=/usr/local/bin:/usr/bin:/bin', '--entrypoint=trivy', trust.trivyImageDigest,
        '--config=/input/trivy.yaml', '--cache-dir=/cache', '--quiet', '--timeout=120s', ...args]);
    };
    const version = JSON.parse(await invoke(['version', '--format=json']));
    if (typeof version.Version !== 'string' || !/^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(version.Version)) throw Error('OCI_TRIVY_VERSION_INVALID');
    toolVersion = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(version.Version) ? version.Version : 'OTHER';
    const images = [], documents = [];
    for (const target of [...new Set([baseImageDigest, imageDigest])]) {
      stage = 'IMAGE_SAVE';
      const info = JSON.parse(await run(['image', 'inspect', target, '--format', '{{json .}}'], 128 * 1024));
      if (info.Id !== target || info.Os !== platform.os || info.Architecture !== platform.architecture) throw Error('OCI_TRIVY_IMAGE_IDENTITY_MISMATCH');
      const archive = await run(['image', 'save', target], OCI_RUNTIME_LIMITS.archiveBytes);
      const ordinal = images.length;
      await writeFile(join(input, `image-${ordinal}.tar`), archive, { flag: 'wx', mode: 0o444 });
      stage = 'VULNERABILITY_SCAN';
      const raw = await invoke(['image', `--input=/input/image-${ordinal}.tar`, '--offline-scan', '--skip-db-update', '--skip-java-db-update',
        '--skip-check-update', '--skip-version-check', '--disable-telemetry', '--scanners=vuln', '--list-all-pkgs',
        '--ignore-unfixed=false', '--ignorefile=/input/empty.ignore', '--format=json']);
      const report = JSON.parse(raw);
      if (report.Metadata?.ImageID !== target || canonicalJson(report.Metadata?.DiffIDs) !== canonicalJson(info.RootFS?.Layers)) throw Error('OCI_TRIVY_REPORT_IDENTITY_INVALID');
      await writeFile(join(input, `report-${ordinal}.json`), raw, { flag: 'wx', mode: 0o444 });
      stage = 'SBOM_CONVERSION';
      const sbom = JSON.parse(await invoke(['convert', '--format=cyclonedx', '--ignorefile=/input/empty.ignore', `/input/report-${ordinal}.json`]));
      contract = trivyContractDiagnostics(report, sbom, target);
      images.push(assessTrivyDocuments(report, sbom, target));
      documents.push({ imageDigest: target, archiveDigest: ociHash(archive), report, sbom });
    }
    stage = 'DATABASE_RECHECK';
    if (await artifactDigest(db, { profile: TRIVY_DATABASE_BUDGET_PROFILE, signal }) !== trust.databaseDigest) throw Error('OCI_TRIVY_DATABASE_IDENTITY_MISMATCH');
    remaining();
    return { status: images.every(({ status }) => status === 'COMPLETE') ? 'COMPLETE' : 'INCONCLUSIVE',
      source: 'LIVE_OFFLINE_TRIVY_CONTAINER', toolImageDigest: trust.trivyImageDigest, toolVersion: version.Version,
      databaseDigest: database.databaseDigest, database: { updatedAt: database.updatedAt, nextUpdate: database.nextUpdate, maxAgeHours: 24 },
      images, highCriticalCount: images.reduce((sum, image) => sum + image.highCriticalCount, 0),
      issues: [...new Set(images.flatMap(({ issues }) => issues))], durationMs: Date.now() - started,
      isolation: { network: 'NONE', user: '1000:1000', capabilities: 'NONE', rootFilesystem: 'READ_ONLY', dockerSocket: 'ABSENT',
        candidateExecutionPerformed: false, databaseUpdate: 'DISABLED', config: 'TRUSTED_EMPTY_CONFIG_AND_IGNORE_FILE' },
      // INTERNAL ONLY: callers must put these documents in encrypted evidence,
      // never in API public result/logs or UI telemetry.
      privateEvidence: { access: 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY', documents } };
  } catch (error) {
    return { status: 'INCONCLUSIVE', issues: [signal.aborted ? 'OCI_TRIVY_TOTAL_TIMEOUT' : /^OCI_[A-Z_]+$/.test(error.message) ? error.message : 'OCI_TRIVY_REVIEW_FAILED'],
      diagnostics: { stage, ...(contract ? { contract } : {}), ...(toolVersion ? { toolVersion } : {}) }, privateEvidence: null };
  } finally {
    for (const container of containers) { try { await runRuntimeDocker(['rm', '-f', container], 5000); } catch { /* exact owned tool container */ } }
    await removeFixtureSnapshot(workspace);
  }
}
