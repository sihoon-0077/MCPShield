import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { writeFile } from "node:fs/promises";
import { compileReleaseRegistry } from "./compile.js";

export async function deployRegistry(
  rpcUrl: string,
  deployerKey: string,
  validators: [string, string, string],
) {
  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new Wallet(deployerKey, provider);
  const compiled = compileReleaseRegistry();
  const factory = new ContractFactory(compiled.abi, compiled.bytecode, signer);
  const contract = await factory.deploy(validators);
  await contract.waitForDeployment();
  return contract;
}

async function main() {
  const rpcUrl = process.env.RPC_URL;
  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const validators = process.env.VALIDATOR_ADDRESSES?.split(",");
  if (!rpcUrl || !deployerKey || validators?.length !== 3) {
    throw new Error(
      "Set RPC_URL, DEPLOYER_PRIVATE_KEY and three comma-separated VALIDATOR_ADDRESSES",
    );
  }
  const contract = await deployRegistry(
    rpcUrl,
    deployerKey,
    validators as [string, string, string],
  );
  const registryAddress = await contract.getAddress();
  const deploymentReceipt = await contract.deploymentTransaction()?.wait();
  if (!deploymentReceipt) throw new Error("Deployment receipt unavailable");
  const deploymentBlock = deploymentReceipt.blockNumber;
  const output = { registryAddress, deploymentBlock };
  if (process.env.DEPLOYMENT_ENV_PATH) {
    await writeFile(process.env.DEPLOYMENT_ENV_PATH,
      `REGISTRY_ADDRESS=${registryAddress}\nATTESTATION_CONTRACT=${registryAddress}\nDEPLOYMENT_BLOCK=${deploymentBlock}\n`,
      "utf8");
  }
  console.log(JSON.stringify(output));
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll("\\", "/")}`) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
