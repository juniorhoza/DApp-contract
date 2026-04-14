// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CredentialRegistry {

    /* =======================
       ROLES & ACCESS CONTROL
       ======================= */
    address public admin;
    address public pendingAdmin;       // two-step admin transfer
    bool    public paused;             // circuit breaker

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

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    /* =======================
       DATA STRUCTURES
       ======================= */
    struct University {
        string name;
        bool   approved;
        bool   suspended;
    }

    struct Credential {
        address student;
        address issuer;
        bytes32 credentialHash;
        string  ipfsCID;
        uint256 issuedAt;
        bool    revoked;
    }

    // ── Transaction log ──────────────────────────────────────────
    enum ActionType {
        UniversityRegistered,
        UniversityApproved,
        UniversitySuspended,
        UniversityUpdated,
        CredentialIssued,
        CredentialRevoked,
        AdminTransferProposed,
        AdminTransferAccepted,
        ContractPaused,
        ContractUnpaused
    }

    struct TxLog {
        ActionType action;
        address    actor;
        bytes32    refId;       // credentialId when relevant, else bytes32(0)
        address    target;      // university / new admin when relevant
        uint256    timestamp;
    }

    /* =======================
       STORAGE
       ======================= */
    mapping(address => University) public universities;
    mapping(bytes32 => Credential) public credentials;
    TxLog[] private _logs;

    /* =======================
       EVENTS
       ======================= */
    event UniversityRegistered     (address university, string name);
    event UniversityApproved       (address university);
    event UniversitySuspended      (address university);
    event UniversityAddressUpdated (address oldAddress, address newAddress);
    event CredentialIssued         (bytes32 indexed credentialId, address indexed student, address indexed issuer, string ipfsCID);
    event CredentialRevoked        (bytes32 indexed credentialId);
    event AdminTransferProposed    (address indexed currentAdmin, address indexed proposed);
    event AdminTransferAccepted    (address indexed newAdmin);
    event ContractPaused           (address indexed by);
    event ContractUnpaused         (address indexed by);

    /* =======================
       INTERNAL LOG HELPER
       ======================= */
    function _log(
        ActionType action,
        address    actor,
        bytes32    refId,
        address    target
    ) internal {
        _logs.push(TxLog({
            action   : action,
            actor    : actor,
            refId    : refId,
            target   : target,
            timestamp: block.timestamp
        }));
    }

    /* =======================
       ADMIN TRANSFER  (two-step)
       ======================= */

    /// @notice Step 1 — propose a new admin. Does not take effect until accepted.
    function proposeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Zero address");
        pendingAdmin = newAdmin;
        emit AdminTransferProposed(admin, newAdmin);
        _log(ActionType.AdminTransferProposed, msg.sender, bytes32(0), newAdmin);
    }

    /// @notice Step 2 — the proposed address must call this to accept.
    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin        = pendingAdmin;
        pendingAdmin = address(0);
        emit AdminTransferAccepted(admin);
        _log(ActionType.AdminTransferAccepted, msg.sender, bytes32(0), admin);
    }

    /* =======================
       PAUSE / UNPAUSE
       ======================= */
    function pause() external onlyAdmin {
        require(!paused, "Already paused");
        paused = true;
        emit ContractPaused(msg.sender);
        _log(ActionType.ContractPaused, msg.sender, bytes32(0), address(0));
    }

    function unpause() external onlyAdmin {
        require(paused, "Not paused");
        paused = false;
        emit ContractUnpaused(msg.sender);
        _log(ActionType.ContractUnpaused, msg.sender, bytes32(0), address(0));
    }

    /* =======================
       UNIVERSITY MANAGEMENT
       ======================= */
    function registerUniversity(string calldata name) external whenNotPaused {
        universities[msg.sender] = University({ name: name, approved: false, suspended: false });
        emit UniversityRegistered(msg.sender, name);
        _log(ActionType.UniversityRegistered, msg.sender, bytes32(0), msg.sender);
    }

    function approveUniversity(address universityAddress) external onlyAdmin whenNotPaused {
        require(!universities[universityAddress].suspended, "University is suspended");
        universities[universityAddress].approved = true;
        emit UniversityApproved(universityAddress);
        _log(ActionType.UniversityApproved, msg.sender, bytes32(0), universityAddress);
    }

    function suspendUniversity(address universityAddress) external onlyAdmin {
        require(universities[universityAddress].approved, "Not an approved university");
        universities[universityAddress].approved  = false;
        universities[universityAddress].suspended = true;
        emit UniversitySuspended(universityAddress);
        _log(ActionType.UniversitySuspended, msg.sender, bytes32(0), universityAddress);
    }

    /// @notice Migrate a university to a new wallet address.
    ///         Old address is wiped; new address inherits name + approval status.
    function updateUniversityAddress(
        address oldAddress,
        address newAddress
    ) external onlyAdmin whenNotPaused {
        require(newAddress != address(0), "Zero address");
        require(universities[oldAddress].approved || bytes(universities[oldAddress].name).length > 0,
                "Old address not registered");
        require(bytes(universities[newAddress].name).length == 0,
                "New address already registered");

        universities[newAddress] = universities[oldAddress];
        delete universities[oldAddress];

        emit UniversityAddressUpdated(oldAddress, newAddress);
        _log(ActionType.UniversityUpdated, msg.sender, bytes32(0), newAddress);
    }

    /* =======================
       CREDENTIAL ISSUANCE
       ======================= */
    function issueCredential(
        bytes32        credentialId,
        address        student,
        bytes32        credentialHash,
        string calldata ipfsCID
    ) external onlyApprovedUniversity whenNotPaused {
        require(credentials[credentialId].issuedAt == 0, "Credential exists");
        credentials[credentialId] = Credential({
            student       : student,
            issuer        : msg.sender,
            credentialHash: credentialHash,
            ipfsCID       : ipfsCID,
            issuedAt      : block.timestamp,
            revoked       : false
        });
        emit CredentialIssued(credentialId, student, msg.sender, ipfsCID);
        _log(ActionType.CredentialIssued, msg.sender, credentialId, student);
    }

    /* =======================
       CREDENTIAL VERIFICATION
       ======================= */
    function verifyCredential(bytes32 credentialId)
        external view
        returns (
            address student,
            address issuer,
            bytes32 credentialHash,
            string memory ipfsCID,
            bool    revoked,
            uint256 issuedAt
        )
    {
        Credential memory c = credentials[credentialId];
        require(c.issuedAt != 0, "Credential not found");
        return (c.student, c.issuer, c.credentialHash, c.ipfsCID, c.revoked, c.issuedAt);
    }

    /* =======================
       REVOCATION
       ======================= */
    function revokeCredential(bytes32 credentialId) external onlyApprovedUniversity whenNotPaused {
        require(credentials[credentialId].issuedAt  != 0,        "Credential not found");
        require(credentials[credentialId].issuer == msg.sender,  "Not the original issuer"); // ✅ bug fix
        credentials[credentialId].revoked = true;
        emit CredentialRevoked(credentialId);
        _log(ActionType.CredentialRevoked, msg.sender, credentialId, credentials[credentialId].student);
    }

    /* =======================
       TRANSACTION LOGS
       ======================= */

    /// @notice Total number of log entries.
    function logCount() external view returns (uint256) {
        return _logs.length;
    }

    /// @notice Fetch a single log entry by index.
    function getLog(uint256 index) external view returns (TxLog memory) {
        require(index < _logs.length, "Index out of range");
        return _logs[index];
    }

    /// @notice Fetch a paginated slice of logs. Pass offset=0, limit=20 to start.
    function getLogs(uint256 offset, uint256 limit)
        external view
        returns (TxLog[] memory page)
    {
        uint256 total = _logs.length;
        if (offset >= total) return new TxLog[](0);
        uint256 end  = offset + limit > total ? total : offset + limit;
        page = new TxLog[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = _logs[i];
        }
    }

    /// @notice Fetch all logs by a specific actor address.
    function getLogsByActor(address actor)
        external view
        returns (TxLog[] memory result)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < _logs.length; i++) {
            if (_logs[i].actor == actor) count++;
        }
        result = new TxLog[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < _logs.length; i++) {
            if (_logs[i].actor == actor) result[j++] = _logs[i];
        }
    }
}