// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BlockchainDNS Registry
 * @notice A decentralized DNS registry that stores domain-to-IP mappings on-chain,
 *         eliminating DNS spoofing, cache poisoning, and registrar-level hijacking.
 * @dev    Domains are owned by wallet addresses. Only the owner can update or transfer.
 *         Records expire and must be renewed, preventing permanent squatting.
 */
contract DNSRegistry {

    // ─── Types ──────────────────────────────────────────────────────────

    enum RecordType { A, AAAA, CNAME, TXT, MX }

    struct DNSRecord {
        string  value;        // IP address, hostname, or text payload
        RecordType recordType;
        uint256 ttl;          // time-to-live in seconds (advisory for caches)
        uint256 updatedAt;
    }

    struct Domain {
        address owner;
        uint256 registeredAt;
        uint256 expiresAt;
        string  primaryValue; // convenience: the "main" A-record value
        uint256 recordCount;
        mapping(uint256 => DNSRecord) records; // index → record
    }

    // ─── State ──────────────────────────────────────────────────────────

    mapping(string => Domain) private domains;
    string[] public domainList;               // for enumeration
    mapping(string => uint256) private domainIndex; // name → index in domainList

    uint256 public constant REGISTRATION_PERIOD = 365 days;
    uint256 public constant MIN_TTL = 60;
    uint256 public constant MAX_RECORDS_PER_DOMAIN = 20;

    // ─── Events ─────────────────────────────────────────────────────────

    event DomainRegistered(string indexed name, address indexed owner, uint256 expiresAt);
    event DomainRenewed(string indexed name, uint256 newExpiry);
    event DomainTransferred(string indexed name, address indexed from, address indexed to);
    event RecordUpdated(string indexed name, uint256 recordIndex, RecordType recordType, string value);
    event RecordDeleted(string indexed name, uint256 recordIndex);

    // ─── Modifiers ──────────────────────────────────────────────────────

    modifier onlyOwner(string calldata name) {
        require(domains[name].owner == msg.sender, "Not domain owner");
        require(block.timestamp < domains[name].expiresAt, "Domain expired");
        _;
    }

    modifier domainExists(string calldata name) {
        require(domains[name].owner != address(0), "Domain not registered");
        _;
    }

    // ─── Registration ───────────────────────────────────────────────────

    /**
     * @notice Register a new domain and bind it to your wallet.
     * @param name       The domain name (e.g. "example.chain")
     * @param ipAddress  The initial A-record value
     * @param ttl        Cache TTL in seconds (>= MIN_TTL)
     */
    function registerDomain(
        string calldata name,
        string calldata ipAddress,
        uint256 ttl
    ) external {
        require(bytes(name).length > 0, "Empty name");
        require(bytes(ipAddress).length > 0, "Empty IP");
        require(ttl >= MIN_TTL, "TTL too low");
        require(
            domains[name].owner == address(0) || block.timestamp >= domains[name].expiresAt,
            "Domain already registered"
        );

        Domain storage d = domains[name];

        // If re-registering an expired domain, clear old records
        if (d.owner != address(0)) {
            for (uint256 i = 0; i < d.recordCount; i++) {
                delete d.records[i];
            }
            d.recordCount = 0;
        } else {
            domainIndex[name] = domainList.length;
            domainList.push(name);
        }

        d.owner        = msg.sender;
        d.registeredAt = block.timestamp;
        d.expiresAt    = block.timestamp + REGISTRATION_PERIOD;
        d.primaryValue = ipAddress;

        // Create the initial A record
        d.records[0] = DNSRecord({
            value:      ipAddress,
            recordType: RecordType.A,
            ttl:        ttl,
            updatedAt:  block.timestamp
        });
        d.recordCount = 1;

        emit DomainRegistered(name, msg.sender, d.expiresAt);
        emit RecordUpdated(name, 0, RecordType.A, ipAddress);
    }

    // ─── Record Management ──────────────────────────────────────────────

    /**
     * @notice Add a new DNS record to a domain you own.
     */
    function addRecord(
        string calldata name,
        RecordType recordType,
        string calldata value,
        uint256 ttl
    ) external onlyOwner(name) {
        Domain storage d = domains[name];
        require(d.recordCount < MAX_RECORDS_PER_DOMAIN, "Max records reached");
        require(ttl >= MIN_TTL, "TTL too low");

        uint256 idx = d.recordCount;
        d.records[idx] = DNSRecord({
            value:      value,
            recordType: recordType,
            ttl:        ttl,
            updatedAt:  block.timestamp
        });
        d.recordCount = idx + 1;

        if (recordType == RecordType.A) {
            d.primaryValue = value;
        }

        emit RecordUpdated(name, idx, recordType, value);
    }

    /**
     * @notice Update an existing record at a given index.
     */
    function updateRecord(
        string calldata name,
        uint256 recordIndex,
        string calldata value,
        uint256 ttl
    ) external onlyOwner(name) {
        Domain storage d = domains[name];
        require(recordIndex < d.recordCount, "Invalid record index");
        require(ttl >= MIN_TTL, "TTL too low");

        DNSRecord storage rec = d.records[recordIndex];
        rec.value     = value;
        rec.ttl       = ttl;
        rec.updatedAt = block.timestamp;

        if (rec.recordType == RecordType.A) {
            d.primaryValue = value;
        }

        emit RecordUpdated(name, recordIndex, rec.recordType, value);
    }

    /**
     * @notice Delete a record by index (swap-and-pop).
     */
    function deleteRecord(
        string calldata name,
        uint256 recordIndex
    ) external onlyOwner(name) {
        Domain storage d = domains[name];
        require(recordIndex < d.recordCount, "Invalid record index");

        uint256 lastIdx = d.recordCount - 1;
        if (recordIndex != lastIdx) {
            d.records[recordIndex] = d.records[lastIdx];
        }
        delete d.records[lastIdx];
        d.recordCount = lastIdx;

        emit RecordDeleted(name, recordIndex);
    }

    // ─── Ownership & Lifecycle ──────────────────────────────────────────

    /**
     * @notice Transfer domain ownership to another address.
     */
    function transferOwnership(
        string calldata name,
        address newOwner
    ) external onlyOwner(name) {
        require(newOwner != address(0), "Invalid address");
        emit DomainTransferred(name, domains[name].owner, newOwner);
        domains[name].owner = newOwner;
    }

    /**
     * @notice Renew a domain for another registration period.
     */
    function renewDomain(string calldata name) external onlyOwner(name) {
        domains[name].expiresAt += REGISTRATION_PERIOD;
        emit DomainRenewed(name, domains[name].expiresAt);
    }

    // ─── Read / Resolve ─────────────────────────────────────────────────

    /**
     * @notice Resolve a domain name → primary IP (the quick lookup).
     */
    function resolveDomain(string calldata name)
        external view domainExists(name)
        returns (string memory ip, address owner, uint256 expiresAt)
    {
        Domain storage d = domains[name];
        require(block.timestamp < d.expiresAt, "Domain expired");
        return (d.primaryValue, d.owner, d.expiresAt);
    }

    /**
     * @notice Get full details for a specific record index.
     */
    function getRecord(string calldata name, uint256 recordIndex)
        external view domainExists(name)
        returns (
            string memory value,
            RecordType recordType,
            uint256 ttl,
            uint256 updatedAt
        )
    {
        Domain storage d = domains[name];
        require(recordIndex < d.recordCount, "Invalid record index");
        DNSRecord storage rec = d.records[recordIndex];
        return (rec.value, rec.recordType, rec.ttl, rec.updatedAt);
    }

    /**
     * @notice Get all records for a domain (batch read).
     */
    function getAllRecords(string calldata name)
        external view domainExists(name)
        returns (
            string[]    memory values,
            RecordType[] memory recordTypes,
            uint256[]   memory ttls,
            uint256[]   memory updatedAts
        )
    {
        Domain storage d = domains[name];
        uint256 count = d.recordCount;

        values      = new string[](count);
        recordTypes = new RecordType[](count);
        ttls        = new uint256[](count);
        updatedAts  = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            DNSRecord storage rec = d.records[i];
            values[i]      = rec.value;
            recordTypes[i] = rec.recordType;
            ttls[i]        = rec.ttl;
            updatedAts[i]  = rec.updatedAt;
        }
    }

    /**
     * @notice Get domain ownership metadata.
     */
    function getDomainInfo(string calldata name)
        external view domainExists(name)
        returns (
            address owner,
            uint256 registeredAt,
            uint256 expiresAt,
            uint256 recordCount
        )
    {
        Domain storage d = domains[name];
        return (d.owner, d.registeredAt, d.expiresAt, d.recordCount);
    }

    /**
     * @notice Total number of domains ever registered.
     */
    function getDomainCount() external view returns (uint256) {
        return domainList.length;
    }

    /**
     * @notice Check if a domain is available for registration.
     */
    function isAvailable(string calldata name) external view returns (bool) {
        return domains[name].owner == address(0) || block.timestamp >= domains[name].expiresAt;
    }
}
