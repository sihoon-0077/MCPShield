import { JsonRpcProvider, Wallet } from "ethers";
import {
  artifactDigestToBytes32,
  chainDecisions,
  createReleaseRegistry,
  releaseKey,
  statusFromChain,
} from "../../../packages/contracts-sdk/src/index.js";
import type {
  ReleaseStatus,
  ValidatorDecision,
} from "../../../packages/protocol/api/types.js";

export interface RegistryClient {
  registerRelease(
    releaseId: string,
    artifactDigest: string,
    toolSurfaceHash: string,
  ): Promise<string>;
  submitVote(
    releaseId: string,
    validatorAddress: string,
    decision: ValidatorDecision,
    evidenceHash: string,
  ): Promise<string>;
  getStatus(releaseId: string): Promise<ReleaseStatus>;
}

export class EvmRegistryClient implements RegistryClient {
  private readonly reader: any;
  private readonly owner: any;
  private readonly validators = new Map<string, any>();

  constructor(
    rpcUrl: string,
    registryAddress: string,
    ownerPrivateKey: string,
    validatorPrivateKeys: string[],
  ) {
    if (validatorPrivateKeys.length !== 3) {
      throw new Error("Exactly three validator private keys are required");
    }
    const provider = new JsonRpcProvider(rpcUrl);
    this.reader = createReleaseRegistry(registryAddress, provider);
    this.owner = createReleaseRegistry(
      registryAddress,
      new Wallet(ownerPrivateKey, provider),
    );
    for (const privateKey of validatorPrivateKeys) {
      const signer = new Wallet(privateKey, provider);
      this.validators.set(
        signer.address.toLowerCase(),
        createReleaseRegistry(registryAddress, signer),
      );
    }
  }

  async registerRelease(
    releaseId: string,
    artifactDigest: string,
    toolSurfaceHash: string,
  ) {
    const tx = await this.owner.registerRelease(
      releaseId,
      artifactDigestToBytes32(artifactDigest),
      toolSurfaceHash,
    );
    await tx.wait();
    return tx.hash as string;
  }

  async submitVote(
    releaseId: string,
    validatorAddress: string,
    decision: ValidatorDecision,
    evidenceHash: string,
  ) {
    const registry = this.validators.get(validatorAddress.toLowerCase());
    if (!registry) throw new Error("VALIDATOR_SIGNER_UNAVAILABLE");
    const tx = await registry.submitVote(
      releaseKey(releaseId),
      chainDecisions[decision],
      evidenceHash,
    );
    await tx.wait();
    return tx.hash as string;
  }

  async getStatus(releaseId: string) {
    const release = await this.reader.getRelease(releaseKey(releaseId));
    return statusFromChain(release.status);
  }
}

export function registryClientFromEnv() {
  const address = process.env.REGISTRY_ADDRESS;
  if (!address) return undefined;
  const rpcUrl = process.env.RPC_URL;
  const ownerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const validatorKeys = process.env.VALIDATOR_PRIVATE_KEYS?.split(",");
  if (!rpcUrl || !ownerKey || validatorKeys?.length !== 3) {
    throw new Error(
      "EVM mode requires RPC_URL, REGISTRY_ADDRESS, DEPLOYER_PRIVATE_KEY and three VALIDATOR_PRIVATE_KEYS",
    );
  }
  return new EvmRegistryClient(rpcUrl, address, ownerKey, validatorKeys);
}
