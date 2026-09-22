import { Contract, type ContractRunner } from "ethers";

export const receiptBatchTypes = { ReceiptBatch: [
  { name: "ledgerKey", type: "bytes32" }, { name: "root", type: "bytes32" },
  { name: "fromSequence", type: "uint64" }, { name: "toSequence", type: "uint64" },
  { name: "previousReceiptHash", type: "bytes32" }, { name: "tipReceiptHash", type: "bytes32" },
  { name: "previousBatchRoot", type: "bytes32" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
] };
export const receiptAnchorDomain = (chainId: number | bigint, verifyingContract: string) => ({
  name: "MCPShieldReceiptAnchorRegistry", version: "1", chainId, verifyingContract,
});
export const receiptAnchorAbi = [
  "function admin() view returns(address)",
  "function ledgers(bytes32) view returns(address writer,uint64 lastSequence,bytes32 receiptHash,bytes32 batchRoot,uint256 nonce)",
  "function rootLedger(bytes32) view returns(bytes32)",
  "function registerLedger(bytes32 ledgerKey,address writer)",
  "function anchor((bytes32 ledgerKey,bytes32 root,uint64 fromSequence,uint64 toSequence,bytes32 previousReceiptHash,bytes32 tipReceiptHash,bytes32 previousBatchRoot,uint256 nonce,uint256 deadline),bytes signature)",
  "event LedgerRegistered(bytes32 indexed ledgerKey,address indexed writer)",
  "event ReceiptBatchAnchored(bytes32 indexed ledgerKey,bytes32 indexed root,uint64 fromSequence,uint64 toSequence,bytes32 previousReceiptHash,bytes32 tipReceiptHash,bytes32 previousBatchRoot,uint256 nonce)",
];
export const createReceiptAnchorRegistry = (address: string, runner: ContractRunner) => new Contract(address, receiptAnchorAbi, runner);
