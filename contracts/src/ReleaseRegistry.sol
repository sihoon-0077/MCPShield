// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MCPShield release verdict registry
/// @notice Stores only release hashes, validator votes, and the resulting state.
///         Raw scan evidence must remain off-chain.
contract ReleaseRegistry {
    enum Status { UNVERIFIED, VERIFIED, QUARANTINED, REVOKED }
    enum Decision { PASS, FAIL, ABSTAIN }

    struct Release {
        string releaseId;
        bytes32 artifactDigest;
        bytes32 toolSurfaceHash;
        Status status;
        uint8 passVotes;
        uint8 failVotes;
        bool exists;
    }

    uint8 public constant QUORUM = 2;
    address public immutable owner;
    mapping(address => bool) public isValidator;
    mapping(bytes32 => Release) private releases;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256) public nonces;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "Attestation(bytes32 releaseKey,uint8 decision,bytes32 evidenceHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant NAME_HASH = keccak256("MCPShield");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant SECP256K1N_DIV_2 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    error OnlyOwner();
    error NotValidator();
    error InvalidValidatorSet();
    error ReleaseAlreadyExists();
    error ReleaseNotFound();
    error AlreadyVoted();
    error ReleaseIsRevoked();
    error AttestationExpired();
    error InvalidNonce();
    error InvalidSignature();

    event ReleaseRegistered(
        bytes32 indexed releaseKey,
        string releaseId,
        bytes32 artifactDigest,
        bytes32 toolSurfaceHash
    );
    event VoteSubmitted(
        bytes32 indexed releaseKey,
        address indexed validator,
        Decision decision,
        bytes32 indexed evidenceHash,
        uint256 nonce
    );
    event StatusChanged(
        bytes32 indexed releaseKey,
        Status previousStatus,
        Status newStatus
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert NotValidator();
        _;
    }

    constructor(address[3] memory validators) {
        if (
            validators[0] == address(0) ||
            validators[1] == address(0) ||
            validators[2] == address(0) ||
            validators[0] == validators[1] ||
            validators[0] == validators[2] ||
            validators[1] == validators[2]
        ) revert InvalidValidatorSet();

        owner = msg.sender;
        for (uint256 i = 0; i < validators.length; i++) {
            isValidator[validators[i]] = true;
        }
    }

    function releaseKey(string memory releaseId) public pure returns (bytes32) {
        return keccak256(bytes(releaseId));
    }

    function registerRelease(
        string calldata releaseId,
        bytes32 artifactDigest,
        bytes32 toolSurfaceHash
    ) external onlyOwner returns (bytes32 key) {
        key = releaseKey(releaseId);
        if (releases[key].exists) revert ReleaseAlreadyExists();

        releases[key] = Release({
            releaseId: releaseId,
            artifactDigest: artifactDigest,
            toolSurfaceHash: toolSurfaceHash,
            status: Status.UNVERIFIED,
            passVotes: 0,
            failVotes: 0,
            exists: true
        });

        emit ReleaseRegistered(key, releaseId, artifactDigest, toolSurfaceHash);
    }

    function submitAttestation(
        bytes32 key,
        Decision decision,
        bytes32 evidenceHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        Release storage item = releases[key];
        if (!item.exists) revert ReleaseNotFound();
        if (item.status == Status.REVOKED) revert ReleaseIsRevoked();
        if (block.timestamp > deadline) revert AttestationExpired();

        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                key,
                uint8(decision),
                evidenceHash,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), structHash)
        );
        address validator = _recover(digest, signature);
        if (!isValidator[validator]) revert NotValidator();
        if (nonce != nonces[validator]) revert InvalidNonce();
        if (hasVoted[key][validator]) revert AlreadyVoted();

        nonces[validator] = nonce + 1;
        hasVoted[key][validator] = true;
        if (decision == Decision.PASS) item.passVotes += 1;
        if (decision == Decision.FAIL) item.failVotes += 1;
        emit VoteSubmitted(key, validator, decision, evidenceHash, nonce);

        Status previous = item.status;
        if (decision == Decision.FAIL) {
            if (item.failVotes >= QUORUM) {
                item.status = Status.REVOKED;
            } else if (
                item.status == Status.UNVERIFIED || item.status == Status.VERIFIED
            ) {
                item.status = Status.QUARANTINED;
            }
        } else if (
            decision == Decision.PASS &&
            item.passVotes >= QUORUM &&
            item.status == Status.UNVERIFIED
        ) {
            item.status = Status.VERIFIED;
        }

        if (item.status != previous) {
            emit StatusChanged(key, previous, item.status);
        }
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1N_DIV_2 || (v != 27 && v != 28)) {
            revert InvalidSignature();
        }
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function getRelease(bytes32 key) external view returns (Release memory) {
        Release memory item = releases[key];
        if (!item.exists) revert ReleaseNotFound();
        return item;
    }
}
