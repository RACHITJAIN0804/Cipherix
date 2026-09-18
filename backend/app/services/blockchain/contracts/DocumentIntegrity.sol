// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DocumentIntegrity {

    struct DocumentRecord {
        bytes32 vaultId;
        bytes32 documentHash;
        uint256 timestamp;
        address recorder;
        bool exists;
    }

    address public owner;
    mapping(address => bool) public authorized;
    mapping(bytes32 => DocumentRecord) private _records;

    event HashRecorded(
        bytes32 indexed documentId,
        bytes32 indexed vaultId,
        bytes32 documentHash,
        address indexed recorder,
        uint256 timestamp
    );
    event AuthorizerAdded(address indexed account);
    event AuthorizerRemoved(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotAuthorized();
    error DocumentAlreadyExists(bytes32 documentId);
    error DocumentNotFound(bytes32 documentId);
    error InvalidHash();
    error InvalidAddress();

    modifier onlyAuthorized() {
        if (!authorized[msg.sender]) revert NotAuthorized();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        authorized[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit AuthorizerAdded(msg.sender);
    }

    function addAuthorized(address account) external onlyOwner {
        if (account == address(0)) revert InvalidAddress();
        authorized[account] = true;
        emit AuthorizerAdded(account);
    }

    function removeAuthorized(address account) external onlyOwner {
        if (account == address(0)) revert InvalidAddress();
        authorized[account] = false;
        emit AuthorizerRemoved(account);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function recordHash(
        bytes32 documentId,
        bytes32 vaultId,
        bytes32 documentHash
    ) external onlyAuthorized {
        if (documentHash == bytes32(0)) revert InvalidHash();
        if (_records[documentId].exists) revert DocumentAlreadyExists(documentId);

        _records[documentId] = DocumentRecord({
            vaultId: vaultId,
            documentHash: documentHash,
            timestamp: block.timestamp,
            recorder: msg.sender,
            exists: true
        });

        emit HashRecorded(documentId, vaultId, documentHash, msg.sender, block.timestamp);
    }

    function getRecord(bytes32 documentId)
        external
        view
        returns (
            bytes32 vaultId,
            bytes32 documentHash,
            uint256 timestamp,
            address recorder
        )
    {
        DocumentRecord storage r = _records[documentId];
        if (!r.exists) revert DocumentNotFound(documentId);
        return (r.vaultId, r.documentHash, r.timestamp, r.recorder);
    }

    function verifyHash(bytes32 documentId, bytes32 hash)
        external
        view
        returns (bool matched, bool exists)
    {
        DocumentRecord storage r = _records[documentId];
        if (!r.exists) return (false, false);
        return (r.documentHash == hash, true);
    }

    function recordExists(bytes32 documentId) external view returns (bool) {
        return _records[documentId].exists;
    }
}
