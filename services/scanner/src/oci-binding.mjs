import { canonicalJson } from './evidence.mjs';
import { hashOciRuntimeDescriptor, ociHash } from '../../resolver/src/oci-runtime-descriptor.mjs';

const sha = /^sha256:[a-f0-9]{64}$/, bytes32 = /^0x[a-f0-9]{64}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join() === [...keys].sort().join();
const anchors = ['baseImageDigest', 'baseCatalogueDigest', 'trivyImageDigest', 'databaseDigest', 'observerDigest', 'sinkImageDigest', 'sinkCodeDigest'];

// Commitments only. These helpers neither approve a release nor acquire trust.
// Every anchor must be independently obtained from operator-local configuration
// and actual bytes before the separate validator policy may use this binding.
export function ociExecutionPolicy(input) {
  if (!exact(input, anchors) || anchors.some((key) => !sha.test(input[key]))) throw Error('OCI_EXECUTION_POLICY_INVALID');
  return { schemaVersion: 'mcpshield.oci-execution-policy.v1', profile: 'restricted-oci-offline-v1', trust: { ...input },
    imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID',
    review: { filesystem: 'STATIC_IMAGE_INVENTORY_NOT_SYSCALL_TRACE', binary: 'EXACT_APPROVED_BASE_PROVENANCE_ONLY',
      semantic: 'ALL_NEW_UTF8_AND_STRUCTURE_BLIND_ANALYZER_CRITIC', unknownBinary: 'ABSTAIN', sourceBytesLimit: 8 * 1024 * 1024,
      sbom: 'TRIVY_DETECTED_PACKAGES_CYCLONEDX', highCriticalVulnerabilities: 'NO_APPROVAL', databaseMaxAgeHours: 24 },
    isolation: { user: '1000:1000', rootFilesystem: 'READ_ONLY', capabilities: 'NONE', privilegeEscalation: 'DENIED',
      seccomp: 'DOCKER_DEFAULT', healthcheck: 'DISABLED', memoryBytes: 256 * 1024 * 1024, cpus: 1, pidsLimit: 64,
      tmpfs: { path: '/tmp', bytes: 32 * 1024 * 1024, noexec: true, nosuid: true } },
    observation: { network: 'INTERNAL_SYNTHETIC_PROXY', egressAllowHosts: ['exfil-sink.local', 'mail-api.local'],
      environment: 'IMAGE_WHITELIST_PLUS_FIXED_SYNTHETIC', home: 'READ_ONLY_SYNTHETIC_CANARIES',
      collector: 'EXTERNAL_MCP_CLIENT', clientSdk: '@modelcontextprotocol/client@2.0.0', protocolMode: '2025_LEGACY_NO_SIBLING_NEGOTIATION' },
    gateway: { profile: 'oci-container-network-none-v1', network: 'NONE', hostMounts: 'NONE', dockerSocket: 'ABSENT',
      environment: 'IMAGE_WHITELIST_NO_HOST_ENV', fixedEnvironment: { HOME: '/nonexistent', PYTHONDONTWRITEBYTECODE: '1' },
      argv: 'EXACT_DESCRIPTOR', workingDirectory: 'EXACT_DESCRIPTOR', mcpProtocol: 'FULL_SURFACE_SCHEMA_AND_PER_CALL_ADMISSION',
      relationToObservation: 'STRICTER_NO_NETWORK_NO_SYNTHETIC_HOME', scope: 'PACKAGED_DATA_OR_COMPUTE_ONLY' } };
}

export function validateOciExecutionPolicy(value) {
  try { return canonicalJson(value) === canonicalJson(ociExecutionPolicy(value.trust)); }
  catch { return false; }
}

export function createOciReleaseBinding(input) {
  if (!exact(input, ['sourceReleaseId', 'descriptor', 'executionPolicy']) || !bytes32.test(input.sourceReleaseId) ||
    !validateOciExecutionPolicy(input.executionPolicy)) throw Error('OCI_BINDING_INVALID');
  const descriptor = structuredClone(input.descriptor), executionPolicy = structuredClone(input.executionPolicy);
  const descriptorDigest = hashOciRuntimeDescriptor(descriptor);
  if (descriptor.stage !== 'OBSERVED' || descriptor.profile !== 'oci-container-v1' || !bytes32.test(descriptor.toolSurfaceHash)) throw Error('OCI_DISCOVERED_DESCRIPTOR_REQUIRED');
  const manifest = { schemaVersion: 'mcpshield.prepared-release.v1', profile: 'oci-container-v1', sourceReleaseId: input.sourceReleaseId,
    sourceArtifactDigest: descriptor.sourceTreeDigest, descriptorDigest, executionPolicyDigest: ociHash(canonicalJson(executionPolicy)) };
  return { ...manifest, artifactDigest: descriptorDigest, manifestDigest: ociHash(canonicalJson(manifest)), toolSurfaceHash: descriptor.toolSurfaceHash,
    descriptor, executionPolicy, finalImageDigest: descriptor.finalImageDigest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID', platform: descriptor.platform };
}

export function validateOciReleaseBinding(value) {
  try { return canonicalJson(value) === canonicalJson(createOciReleaseBinding({ sourceReleaseId: value.sourceReleaseId,
    descriptor: value.descriptor, executionPolicy: value.executionPolicy })); }
  catch { return false; }
}
