import { ContractFactory, JsonRpcProvider, NonceManager, Wallet } from "ethers";
import { v2RpcRequest } from "../../packages/contracts-sdk/src/transport.js";
import { pathToFileURL } from "node:url";
import { compileReleaseRegistry } from "./compile.js";

export type RegistryContract = "ReleaseRegistryV2" | "ReleaseRegistryV3";
// V3 (ADR-008) shares ValidatorRegistry, PolicyRegistry and the constructor with V2; only the release registry differs.
export async function deployV2(rpcUrl: string, key: string, validators: string[], expectedChainId: number, admin?: string,
  registryContract: RegistryContract = "ReleaseRegistryV2") {
  const request = v2RpcRequest(rpcUrl);
  const provider = new JsonRpcProvider(request, undefined, { batchMaxCount: 1 });
  try {
    const wallet = new Wallet(key, provider), signer = new NonceManager(wallet);
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(expectedChainId)) throw new Error("CHAIN_ID_MISMATCH");
    if (validators.length !== 3 || new Set(validators.map((value) => value.toLowerCase())).size !== 3) throw new Error("THREE_UNIQUE_VALIDATORS_REQUIRED");
    const deploy = async (name: string, args: any[]) => {
      const compiled = compileReleaseRegistry(name), factory = new ContractFactory(compiled.abi, compiled.bytecode, signer);
      const contract = await factory.deploy(...args); await contract.waitForDeployment();
      const receipt = await contract.deploymentTransaction()!.wait(); if (!receipt) throw new Error("DEPLOYMENT_RECEIPT_MISSING");
      return { address: await contract.getAddress(), txHash: receipt.hash, blockNumber: receipt.blockNumber };
    };
    const owner = admin ?? wallet.address;
    const validatorRegistry = await deploy("ValidatorRegistry", [owner, validators]);
    const policyRegistry = await deploy("PolicyRegistry", [owner]);
    const releaseRegistry = await deploy(registryContract, [wallet.address, validatorRegistry.address, policyRegistry.address]);
    return { chainId: expectedChainId, registryContract, owner, relayer: wallet.address, validatorRegistry, policyRegistry, releaseRegistry,
      validatorAddresses: validators, governance: admin ? "EXTERNAL_ADMIN" : "SINGLE_INSTITUTION_DEMO", upgradeable: false };
  } finally { provider.destroy(); }
}
async function main() {
  const { CONTROL_V2_RPC_URLS, DEPLOYER_PRIVATE_KEY, VALIDATOR_ADDRESSES, CONTROL_V2_CHAIN_ID } = process.env;
  if (!CONTROL_V2_RPC_URLS || !DEPLOYER_PRIVATE_KEY || !VALIDATOR_ADDRESSES || !CONTROL_V2_CHAIN_ID) throw new Error("V2_RPC_KEY_VALIDATORS_CHAIN_ID_REQUIRED");
  const rpc = CONTROL_V2_RPC_URLS.split(",")[0];
  if (!process.argv.includes("--deploy")) {
    const provider = new JsonRpcProvider(v2RpcRequest(rpc));
    try {
      const wallet = new Wallet(DEPLOYER_PRIVATE_KEY, provider), network = await provider.getNetwork();
      if (network.chainId !== BigInt(CONTROL_V2_CHAIN_ID)) throw new Error("CHAIN_ID_MISMATCH");
      console.log(JSON.stringify({ preflight: true, chainId: Number(network.chainId), deployer: wallet.address, balanceWei: (await provider.getBalance(wallet.address)).toString(), deployFlagRequired: true }));
    } finally { provider.destroy(); }
    return;
  }
  const registry: RegistryContract = process.argv.includes("--v3") ? "ReleaseRegistryV3" : "ReleaseRegistryV2";
  console.log(JSON.stringify(await deployV2(rpc, DEPLOYER_PRIVATE_KEY, VALIDATOR_ADDRESSES.split(","), Number(CONTROL_V2_CHAIN_ID), process.env.V2_GOVERNANCE_ADMIN, registry)));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
