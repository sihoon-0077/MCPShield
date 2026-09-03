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

    error OnlyOwner();
    error NotValidator();
    error InvalidValidatorSet();
    error ReleaseAlreadyExists();
    error ReleaseNotFound();
    error AlreadyVoted();
    error ReleaseIsRevoked();

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
        bytes32 indexed evidenceHash
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

    function submitVote(
        bytes32 key,
        Decision decision,
        bytes32 evidenceHash
    ) external onlyValidator {
        Release storage item = releases[key];
        if (!item.exists) revert ReleaseNotFound();
        if (item.status == Status.REVOKED) revert ReleaseIsRevoked();
        if (hasVoted[key][msg.sender]) revert AlreadyVoted();

        hasVoted[key][msg.sender] = true;
        if (decision == Decision.PASS) item.passVotes += 1;
        if (decision == Decision.FAIL) item.failVotes += 1;
        emit VoteSubmitted(key, msg.sender, decision, evidenceHash);

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

    function getRelease(bytes32 key) external view returns (Release memory) {
        Release memory item = releases[key];
        if (!item.exists) revert ReleaseNotFound();
        return item;
    }
}
