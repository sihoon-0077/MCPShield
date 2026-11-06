import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { pathToFileURL } from "node:url";
import { v2RpcRequest } from "../../packages/contracts-sdk/src/transport.js";
import { compileReleaseRegistry } from "./compile.js";

export async function deployReceipts(rpcUrl: string, key: string, expectedChainId: number, admin?: string) {
  const provider = new JsonRpcProvider(v2RpcRequest(rpcUrl), undefined, { batchMaxCount: 1 }), signer = new Wallet(key, provider);
  try {
    if ((await provider.getNetwork()).chainId !== BigInt(expectedChainId)) throw new Error("CHAIN_ID_MISMATCH");
    const compiled = compileReleaseRegistry("ReceiptAnchorRegistry"), contract = await new ContractFactory(compiled.abi, compiled.bytecode, signer).deploy(admin ?? signer.address);
    const receipt = await contract.deploymentTransaction()!.wait(); if (!receipt) throw new Error("DEPLOYMENT_RECEIPT_MISSING");
    return { chainId: expectedChainId, registryAddress: await contract.getAddress(), admin: admin ?? signer.address, txHash: receipt.hash,
      blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed.toString(), upgradeable: false, governance: admin ? "EXTERNAL_ADMIN" : "SINGLE_INSTITUTION_DEMO" };
  } finally { provider.destroy(); }
}
async function main() {
  const { CONTROL_RECEIPT_RPC_URL, CONTROL_RECEIPT_CHAIN_ID, DEPLOYER_PRIVATE_KEY } = process.env;
  if (!CONTROL_RECEIPT_RPC_URL || !CONTROL_RECEIPT_CHAIN_ID || !DEPLOYER_PRIVATE_KEY || !process.argv.includes("--deploy")) throw new Error("RECEIPT_RPC_CHAIN_KEY_AND_DEPLOY_FLAG_REQUIRED");
  console.log(JSON.stringify(await deployReceipts(CONTROL_RECEIPT_RPC_URL, DEPLOYER_PRIVATE_KEY, Number(CONTROL_RECEIPT_CHAIN_ID), process.env.RECEIPT_GOVERNANCE_ADMIN)));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error("RECEIPT_DEPLOYMENT_FAILED"); process.exitCode = 1; });
