import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import type { InterfaceAbi } from "ethers";

export interface CompiledContract {
  abi: InterfaceAbi;
  bytecode: string;
}

export function compileReleaseRegistry(contractName = "ReleaseRegistry"): CompiledContract {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const sourceName = ["ReleaseRegistry", "ReceiptAnchorRegistry"].includes(contractName) ? `${contractName}.sol` : "ReleaseRegistryV2.sol";
  if (!["ReleaseRegistry", "ReleaseRegistryV2", "ValidatorRegistry", "PolicyRegistry", "ReceiptAnchorRegistry"].includes(contractName)) throw new Error("Unknown contract");
  const sourcePath = path.resolve(here, "../src", sourceName);
  const source = fs.readFileSync(sourcePath, "utf8");
  const input = {
    language: "Solidity",
    sources: { [sourceName]: { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: contractName !== "ReleaseRegistry",
      evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(
    (entry: { severity: string }) => entry.severity === "error",
  );
  if (errors.length > 0) {
    throw new Error(errors.map((entry: { formattedMessage: string }) => entry.formattedMessage).join("\n"));
  }
  const contract = output.contracts[sourceName][contractName];
  return { abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}` };
}
