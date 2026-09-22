// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Optional checkpoints, not proof that an off-chain action was safe or actually executed.
/// No tenant, agent, tool name, arguments or receipt plaintext is stored here.
contract ReceiptAnchorRegistry {
    address public immutable admin;
    struct Ledger { address writer; uint64 lastSequence; bytes32 receiptHash; bytes32 batchRoot; uint256 nonce; }
    struct ReceiptBatch {
        bytes32 ledgerKey; bytes32 root; uint64 fromSequence; uint64 toSequence;
        bytes32 previousReceiptHash; bytes32 tipReceiptHash; bytes32 previousBatchRoot;
        uint256 nonce; uint256 deadline;
    }
    mapping(bytes32 => Ledger) public ledgers;
    mapping(bytes32 => bytes32) public rootLedger;
    bytes32 private constant TYPEHASH = keccak256("ReceiptBatch(bytes32 ledgerKey,bytes32 root,uint64 fromSequence,uint64 toSequence,bytes32 previousReceiptHash,bytes32 tipReceiptHash,bytes32 previousBatchRoot,uint256 nonce,uint256 deadline)");
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    event LedgerRegistered(bytes32 indexed ledgerKey, address indexed writer);
    event ReceiptBatchAnchored(bytes32 indexed ledgerKey, bytes32 indexed root, uint64 fromSequence, uint64 toSequence,
        bytes32 previousReceiptHash, bytes32 tipReceiptHash, bytes32 previousBatchRoot, uint256 nonce);

    constructor(address owner) { require(owner != address(0), "ZERO_ADMIN"); admin = owner; }
    function registerLedger(bytes32 ledgerKey, address writer) external {
        require(msg.sender == admin, "NOT_ADMIN");
        require(ledgerKey != bytes32(0) && writer != address(0), "INVALID_LEDGER");
        require(ledgers[ledgerKey].writer == address(0), "LEDGER_EXISTS");
        ledgers[ledgerKey].writer = writer;
        emit LedgerRegistered(ledgerKey, writer);
    }
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("MCPShieldReceiptAnchorRegistry"), keccak256("1"), block.chainid, address(this)));
    }
    function anchor(ReceiptBatch calldata b, bytes calldata signature) external {
        Ledger storage ledger = ledgers[b.ledgerKey];
        require(ledger.writer != address(0), "UNKNOWN_LEDGER");
        require(b.root != bytes32(0) && b.tipReceiptHash != bytes32(0) && rootLedger[b.root] == bytes32(0), "ROOT_REPLAY");
        require(b.fromSequence == ledger.lastSequence + 1 && b.toSequence >= b.fromSequence && b.toSequence - b.fromSequence < 127, "INVALID_RANGE");
        require(b.previousReceiptHash == ledger.receiptHash && b.previousBatchRoot == ledger.batchRoot, "CHECKPOINT_MISMATCH");
        require(b.nonce == ledger.nonce, "NONCE_MISMATCH");
        require(block.timestamp <= b.deadline && b.deadline <= block.timestamp + 1 hours, "INVALID_DEADLINE");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(TYPEHASH, b))));
        require(signature.length == 65, "INVALID_SIGNATURE");
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        require(uint256(s) <= HALF_N && (v == 27 || v == 28), "INVALID_SIGNATURE");
        require(ecrecover(digest, v, r, s) == ledger.writer, "WRITER_MISMATCH");
        ledger.lastSequence = b.toSequence; ledger.receiptHash = b.tipReceiptHash;
        ledger.batchRoot = b.root; ledger.nonce++;
        rootLedger[b.root] = b.ledgerKey;
        emit ReceiptBatchAnchored(b.ledgerKey, b.root, b.fromSequence, b.toSequence, b.previousReceiptHash, b.tipReceiptHash, b.previousBatchRoot, b.nonce);
    }
}
