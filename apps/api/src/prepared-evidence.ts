import { bytes32, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
import { canonical } from "./control-plane.js";
// @ts-expect-error Shared pure scanner binding is ESM JavaScript.
import { validatePreparedReleaseBinding } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared strict OCI binding, intentionally separate from the Node binding validator.
import { validateOciReleaseBinding } from "../../../services/scanner/src/oci-binding.mjs";
// @ts-expect-error Shared scanner surface identity is ESM JavaScript.
import { toolSurfaceHash } from "../../../services/scanner/src/tool-surface.mjs";

// Pure independent commitment verification. A valid identity does not assert behavior, PASS, or chain state.
export function checkedPreparedEvidence(bundle: any, identity?: any) {
  return checkedRuntimeEvidence(bundle, identity, false);
}
export function checkedOciEvidence(bundle: any, identity?: any) {
  return checkedRuntimeEvidence(bundle, identity, true);
}
function checkedRuntimeEvidence(bundle: any, identity: any, oci: boolean) {
  const binding = JSON.parse(bundle.files[oci ? "oci/binding.json" : "prepared/binding.json"] ?? "null"), source = JSON.parse(bundle.files["prepared/source-identity.json"] ?? "null");
  const tools = JSON.parse(bundle.files["runtime/tools.json"] ?? "null");
  if (!(oci ? validateOciReleaseBinding(binding) : validatePreparedReleaseBinding(binding))
    || bundle.files[oci ? "prepared/binding.json" : "oci/binding.json"] !== undefined
    || !source || Object.keys(source).sort().join() !== "artifactDigest,manifestDigest,releaseId,toolId,toolSurfaceHash"
    || exactReleaseIdentity(source).releaseId !== source.releaseId || source.releaseId !== binding.sourceReleaseId
    || source.artifactDigest !== binding.sourceArtifactDigest || !Array.isArray(tools) || tools.length > 128
    || toolSurfaceHash(tools) !== binding.toolSurfaceHash
    || canonical(JSON.parse(bundle.files[oci ? "runtime/oci-descriptor.json" : "runtime/descriptor.json"] ?? "null")) !== canonical(binding.descriptor)
    || canonical(JSON.parse(bundle.files["runtime/execution-policy.json"] ?? "null")) !== canonical(binding.executionPolicy)) throw new Error("PREPARED_EVIDENCE_IDENTITY_MISMATCH");
  const exact = exactReleaseIdentity({ toolId: source.toolId, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
  if (identity && (bytes32(identity.toolId) !== exact.toolId || bytes32(identity.artifactDigest) !== bytes32(binding.artifactDigest)
    || bytes32(identity.manifestDigest) !== bytes32(binding.manifestDigest) || bytes32(identity.toolSurfaceHash ?? identity.toolSurfaceDigest) !== binding.toolSurfaceHash
    || identity.releaseId !== undefined && identity.releaseId !== exact.releaseId)) throw new Error("PREPARED_RELEASE_IDENTITY_MISMATCH");
  return { binding, source, tools, identity: exact };
}
