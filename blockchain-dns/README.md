# Blockchain DNS — Spoof-Proof Domain Resolution

A decentralized DNS system built on Ethereum that eliminates DNS spoofing, cache poisoning, and registrar-level hijacking by storing domain records on an immutable blockchain ledger.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Browser /   │────▶│  Local Resolver   │────▶│  Ethereum Chain  │
│  OS Client   │◀────│  (Python UDP)     │◀────│  (DNSRegistry)   │
└─────────────┘     └──────┬───────────┘     └─────────────────┘
                           │ fallback
                           ▼
                    ┌──────────────┐
                    │  Google DNS   │  (for non-.chain domains)
                    │  8.8.8.8     │
                    └──────────────┘
```

### Components

| Component | Location | Description |
|-----------|----------|-------------|
| **Smart Contract** | `contracts/DNSRegistry.sol` | Solidity registry — stores domain→IP mappings, enforces ownership via wallet signatures |
| **DNS Resolver** | `resolver/resolver.py` | Python UDP server — intercepts DNS queries, resolves `.chain` domains from the blockchain |
| **Deploy Script** | `scripts/deploy.js` | Hardhat deployment with sample domains |
| **Tests** | `test/DNSRegistry.test.js` | Comprehensive contract tests (registration, anti-spoofing, record CRUD, transfers) |
| **Resolver Tests** | `test/test_resolver.py` | End-to-end resolver test suite with spoofing resistance demo |
| **Dashboard** | `frontend/` | React management UI (run as artifact or standalone) |

## Quick Start

### 1. Install & Compile

```bash
npm install
npx hardhat compile
```

### 2. Start Local Blockchain

```bash
npx hardhat node
```

### 3. Deploy Contract

```bash
npx hardhat run scripts/deploy.js --network localhost
```

### 4. Run Tests

```bash
# Smart contract tests
npx hardhat test

# Resolver tests (start resolver first)
python resolver/resolver.py --demo &
python test/test_resolver.py
```

### 5. Start the Resolver

**Demo mode** (no blockchain needed):
```bash
python resolver/resolver.py --demo --port 5553
```

**With blockchain**:
```bash
python resolver/resolver.py --rpc-url http://127.0.0.1:8545 --contract 0xYOUR_ADDRESS --port 5553
```

### 6. Test DNS Queries

```bash
# Resolve a blockchain domain
dig @127.0.0.1 -p 5553 example.chain

# Resolve a traditional domain (falls through to 8.8.8.8)
dig @127.0.0.1 -p 5553 google.com
```

## Security Model

### What It Prevents

| Attack | Traditional DNS | Blockchain DNS |
|--------|----------------|----------------|
| **DNS Spoofing** | Attacker forges response → user visits malicious site | Resolver verifies against on-chain record → forged response rejected |
| **Cache Poisoning** | Attacker poisons resolver cache | Cache is validated against immutable chain state |
| **Registrar Hijack** | Attacker compromises registrar account | No registrar — ownership proved by private key |
| **Record Tampering** | Attacker modifies zone file on nameserver | Records are immutable on-chain; updates need owner's signature |

### How Ownership Works

1. User registers `mysite.chain` → wallet address becomes owner
2. Only that wallet's private key can sign transactions to update records
3. Ownership transfer requires explicit on-chain transaction
4. Every change is permanently logged as a blockchain event

## Demo: Spoofing Attack Comparison

### Traditional DNS (vulnerable)

```bash
# Attacker runs ettercap/bettercap to ARP-spoof the network
# Attacker intercepts DNS query for example.com
# Attacker responds with malicious IP → user redirected
```

### Blockchain DNS (immune)

```bash
# Same attack scenario, but:
# Resolver receives forged response with malicious IP
# Resolver queries blockchain for example.chain
# On-chain record says IP = 93.184.216.34
# Forged IP ≠ on-chain IP → forged response REJECTED
# User gets the legitimate IP from the immutable ledger
```

## Project Structure

```
blockchain-dns/
├── contracts/
│   └── DNSRegistry.sol        # Core smart contract
├── resolver/
│   └── resolver.py            # Python DNS resolver with blockchain backend
├── scripts/
│   └── deploy.js              # Hardhat deployment script
├── test/
│   ├── DNSRegistry.test.js    # Smart contract tests
│   └── test_resolver.py       # Resolver integration tests
├── frontend/                  # React dashboard (see artifact)
├── hardhat.config.js
├── package.json
└── README.md
```

## Extending the Project

- **IPFS integration** — store large TXT records or website content on IPFS, reference by CID
- **DAO governance** — dispute resolution via token-weighted voting
- **Layer 2 deployment** — deploy on Polygon/Arbitrum for cheaper transactions
- **DNSSEC bridge** — verify traditional DNSSEC signatures alongside on-chain records
- **ENS compatibility** — support `.eth` resolution alongside `.chain`

## References

- [Ethereum Name Service (ENS)](https://ens.domains/)
- [Handshake (HNS)](https://handshake.org/)
- [EIP-137: Ethereum Domain Name Service](https://eips.ethereum.org/EIPS/eip-137)
