// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CredentialRegistry {

    /* =======================
       ROLES & ACCESS CONTROL
       ======================= */

    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin allowed");
        _;
    }

    modifier onlyApprovedUniversity() {
        require(universities[msg.sender].approved, "University not approved");
        _;
    }

    /* =======================
       DATA STRUCTURES
       ======================= */

    struct University {
        string name;
        bool approved;
    }

    struct Credential {
        address student;
        address issuer;
        bytes32 credentialHash;   // SHA-256 hash
        string ipfsCID;            // IPFS metadata/document
        uint256 issuedAt;
        bool revoked;
    }

    /* =======================
       STORAGE
       ======================= */

    mapping(address => University) public universities;
    mapping(bytes32 => Credential) public credentials;

    /* =======================
       EVENTS 
       ======================= */

    event UniversityRegistered(address university, string name);
    event UniversityApproved(address university);
    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed student,
        address indexed issuer,
        string ipfsCID
    );
    event CredentialRevoked(bytes32 indexed credentialId);

    /* =======================
       UNIVERSITY MANAGEMENT
       ======================= */

    function registerUniversity(string calldata name) external {
        universities[msg.sender] = University({
            name: name,
            approved: false
        });

        emit UniversityRegistered(msg.sender, name);
    }

    function approveUniversity(address universityAddress)
        external
        onlyAdmin
    {
        universities[universityAddress].approved = true;
        emit UniversityApproved(universityAddress);
    }

    /* =======================
       CREDENTIAL ISSUANCE
       ======================= */

    function issueCredential(
        bytes32 credentialId,
        address student,
        bytes32 credentialHash,
        string calldata ipfsCID
    ) external onlyApprovedUniversity {

        require(credentials[credentialId].issuedAt == 0, "Credential exists");

        credentials[credentialId] = Credential({
            student: student,
            issuer: msg.sender,
            credentialHash: credentialHash,
            ipfsCID: ipfsCID,
            issuedAt: block.timestamp,
            revoked: false
        });

        emit CredentialIssued(
            credentialId,
            student,
            msg.sender,
            ipfsCID
        );
    }

    /* =======================
       CREDENTIAL VERIFICATION
       ======================= */

    function verifyCredential(bytes32 credentialId)
        external
        view
        returns (
            address student,
            address issuer,
            bytes32 credentialHash,
            string memory ipfsCID,
            bool revoked,
            uint256 issuedAt
        )
    {
        Credential memory c = credentials[credentialId];
        require(c.issuedAt != 0, "Credential not found");

        return (
            c.student,
            c.issuer,
            c.credentialHash,
            c.ipfsCID,
            c.revoked,
            c.issuedAt
        );
    }

    /* =======================
       REVOCATION
       ======================= */

    function revokeCredential(bytes32 credentialId)
        external
        onlyApprovedUniversity
    {
        require(credentials[credentialId].issuedAt != 0, "Credential not found");
        credentials[credentialId].revoked = true;

        emit CredentialRevoked(credentialId);
    }
}
