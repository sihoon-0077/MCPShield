import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import type { InterfaceAbi } from "ethers";

export interface CompiledContract {
  abi: InterfaceAbi;
  bytecode: string;
}

// solc-js is synchronous and blocks the event loop for seconds, which can time out RPC requests in flight in the same
// process (an in-process test chain cannot answer meanwhile). Each source is compiled once per process.
const outputs = new Map<string, any>();

export function compileReleaseRegistry(contractName = "ReleaseRegistry"): CompiledContract {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const sourceName = ["ReleaseRegistry", "ReceiptAnchorRegistry", "ReleaseRegistryV3"].includes(contractName) ? `${contractName}.sol` : "ReleaseRegistryV2.sol";
  if (!["ReleaseRegistry", "ReleaseRegistryV2", "ReleaseRegistryV3", "ValidatorRegistry", "PolicyRegistry", "ReceiptAnchorRegistry"].includes(contractName)) throw new Error("Unknown contract");
  const key = `${sourceName}|viaIR=${contractName !== "ReleaseRegistry"}`;
  const output = outputs.get(key) ?? compileSource(here, sourceName, contractName !== "ReleaseRegistry");
  outputs.set(key, output);
  const contract = output.contracts[sourceName][contractName];
  return { abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}` };
}

function compileSource(here: string, sourceName: string, viaIR: boolean) {
  const sourcePath = path.resolve(here, "../src", sourceName);
  const source = fs.readFileSync(sourcePath, "utf8");
  const input = {
    language: "Solidity",
    sources: { [sourceName]: { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR,
      evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  // Only sibling sources in contracts/src may be imported (V3 imports the V2 registries).
  const findImports = (importPath: string) => /^[A-Za-z0-9]+\.sol$/.test(importPath)
    ? { contents: fs.readFileSync(path.resolve(here, "../src", importPath), "utf8") } : { error: "IMPORT_NOT_ALLOWED" };
  const output = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));
  const errors = (output.errors ?? []).filter(
    (entry: { severity: string }) => entry.severity === "error",
  );
  if (errors.length > 0) {
    throw new Error(errors.map((entry: { formattedMessage: string }) => entry.formattedMessage).join("\n"));
  }
  return output;
}
