import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import type { InterfaceAbi } from "ethers";

export interface CompiledContract {
  abi: InterfaceAbi;
  bytecode: string;
}

export function compileReleaseRegistry(): CompiledContract {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const sourcePath = path.resolve(here, "../src/ReleaseRegistry.sol");
  const source = fs.readFileSync(sourcePath, "utf8");
  const input = {
    language: "Solidity",
    sources: { "ReleaseRegistry.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
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
  const contract = output.contracts["ReleaseRegistry.sol"].ReleaseRegistry;
  return { abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}` };
}
