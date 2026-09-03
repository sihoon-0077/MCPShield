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

export interface SignedAttestation {
  releaseId: string;
  decision: ValidatorDecision;
  evidenceHash: string;
  nonce: number;
  deadline: number;
  signature: string;
}

export interface ChainRelease {
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
  status: ReleaseStatus;
}

export interface SubmittedTransaction {
  hash: string;
  wait(): Promise<void>;
}

export interface RegistryClient {
  registerRelease(
    releaseId: string,
    artifactDigest: string,
    toolSurfaceHash: string,
  ): Promise<SubmittedTransaction>;
  submitAttestation(attestation: SignedAttestation): Promise<SubmittedTransaction>;
  getRelease(releaseId: string): Promise<ChainRelease>;
  findRelease(releaseId: string): Promise<ChainRelease | undefined>;
  getValidatorNonce(validatorAddress: string): Promise<number>;
  hasVoted(releaseId: string, validatorAddress: string): Promise<boolean>;
  getReceipt(txHash: string): Promise<"PENDING" | "SUCCESS" | "REVERTED">;
  validateConnection(expectedChainId?: number, validators?: string[]): Promise<void>;
}

function withDeadline<T>(promise: Promise<T>, timeoutMs: number, operation: string) {
  let timer: NodeJS.Timeout;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`RPC_TIMEOUT:${operation}`)), timeoutMs);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer!));
}

export class EvmRegistryClient implements RegistryClient {
  private readonly provider: JsonRpcProvider;
  private readonly reader: any;
  private readonly relayer: any;
  private readonly relayerAddress: string;

  constructor(
    rpcUrl: string,
    private readonly registryAddress: string,
    relayerPrivateKey: string,
    private readonly timeoutMs = 5_000,
  ) {
    this.provider = new JsonRpcProvider(rpcUrl);
    this.reader = createReleaseRegistry(registryAddress, this.provider);
    const signer = new Wallet(relayerPrivateKey, this.provider);
    this.relayerAddress = signer.address;
    this.relayer = createReleaseRegistry(registryAddress, signer);
  }

  async validateConnection(expectedChainId?: number, validators: string[] = []) {
    const code = await withDeadline(
      this.provider.getCode(this.registryAddress),
      this.timeoutMs,
      "getCode",
    );
    if (code === "0x") throw new Error("REGISTRY_CONTRACT_NOT_FOUND");
    await withDeadline(this.reader.QUORUM(), this.timeoutMs, "quorum");
    const owner = await withDeadline<any>(this.reader.owner(), this.timeoutMs, "owner");
    if (String(owner).toLowerCase() !== this.relayerAddress.toLowerCase()) {
      throw new Error("RELAYER_MUST_BE_REGISTRY_OWNER_FOR_RELEASE_REGISTRATION");
    }
    const network = await withDeadline(
      this.provider.getNetwork(), this.timeoutMs, "network",
    );
    if (expectedChainId && network.chainId !== BigInt(expectedChainId)) {
      throw new Error("ATTESTATION_CHAIN_ID_MISMATCH");
    }
    for (const validator of validators) {
      const configured = await withDeadline<any>(
        this.reader.isValidator(validator), this.timeoutMs, "isValidator",
      );
      if (!configured) throw new Error(`VALIDATOR_NOT_REGISTERED:${validator}`);
    }
  }

  async registerRelease(
    releaseId: string,
    artifactDigest: string,
    toolSurfaceHash: string,
  ) {
    const tx = await withDeadline<any>(
      this.relayer.registerRelease(
        releaseId,
        artifactDigestToBytes32(artifactDigest),
        toolSurfaceHash,
      ),
      this.timeoutMs,
      "registerRelease",
    );
    return {
      hash: tx.hash as string,
      wait: async () => {
        await withDeadline(tx.wait(), this.timeoutMs, "registerReleaseReceipt");
      },
    };
  }

  async submitAttestation(attestation: SignedAttestation) {
    const tx = await withDeadline<any>(
      this.relayer.submitAttestation(
        releaseKey(attestation.releaseId),
        chainDecisions[attestation.decision],
        attestation.evidenceHash,
        attestation.nonce,
        attestation.deadline,
        attestation.signature,
      ),
      this.timeoutMs,
      "submitAttestation",
    );
    return {
      hash: tx.hash as string,
      wait: async () => {
        await withDeadline(tx.wait(), this.timeoutMs, "attestationReceipt");
      },
    };
  }

  async getRelease(releaseId: string): Promise<ChainRelease> {
    const release = await withDeadline<any>(
      this.reader.getRelease(releaseKey(releaseId)),
      this.timeoutMs,
      "getRelease",
    );
    return {
      releaseId: release.releaseId,
      artifactDigest: `sha256:${String(release.artifactDigest).slice(2).toLowerCase()}`,
      toolSurfaceHash: String(release.toolSurfaceHash).toLowerCase(),
      status: statusFromChain(release.status),
    };
  }

  async findRelease(releaseId: string) {
    try {
      return await this.getRelease(releaseId);
    } catch (error) {
      if ((error as { code?: string }).code === "CALL_EXCEPTION") return undefined;
      throw error;
    }
  }

  async getValidatorNonce(validatorAddress: string) {
    const nonce = await withDeadline<any>(
      this.reader.nonces(validatorAddress), this.timeoutMs, "validatorNonce",
    );
    return Number(nonce);
  }

  async hasVoted(releaseId: string, validatorAddress: string) {
    return Boolean(await withDeadline<any>(
      this.reader.hasVoted(releaseKey(releaseId), validatorAddress),
      this.timeoutMs,
      "hasVoted",
    ));
  }

  async getReceipt(txHash: string) {
    const receipt = await withDeadline(
      this.provider.getTransactionReceipt(txHash), this.timeoutMs, "transactionReceipt",
    );
    if (!receipt) return "PENDING" as const;
    return receipt.status === 1 ? "SUCCESS" as const : "REVERTED" as const;
  }
}

export function registryClientFromEnv() {
  const address = process.env.REGISTRY_ADDRESS;
  if (!address) return undefined;
  const rpcUrl = process.env.RPC_URL;
  const relayerKey = process.env.RELAYER_PRIVATE_KEY;
  if (!rpcUrl || !relayerKey) {
    throw new Error(
      "EVM mode requires RPC_URL, REGISTRY_ADDRESS and RELAYER_PRIVATE_KEY",
    );
  }
  return new EvmRegistryClient(
    rpcUrl,
    address,
    relayerKey,
    Number(process.env.RPC_TIMEOUT_MS || 5_000),
  );
}
