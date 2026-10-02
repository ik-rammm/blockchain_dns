# Blockchain DNS — SOC Platform

A **Security Operations Center** web app that sits in the DNS resolution path,
traces every query in real time, and proves that **nothing is forged** by
comparing every observed answer against an immutable, hash-linked blockchain
ledger. Any attempt to spoof a DNS response — or to tamper with the ledger
itself — is detected and surfaced live on the dashboard.

```
┌───────────────┐   query    ┌────────────────────┐   compare   ┌──────────────────┐
│  DNS clients   │──────────▶│   SOC Tracer        │────────────▶│  Hash-linked     │
│  / resolvers   │◀──────────│  (verdict engine)   │◀────────────│  Blockchain      │
└───────────────┘  verdict   └─────────┬──────────┘   truth      │  (source of truth)│
                                        │ WebSocket               └──────────────────┘
                                        ▼
                              ┌────────────────────┐
                              │  SOC Dashboard      │  live feed · threats · ledger ·
                              │  (browser)          │  integrity scan · attack sims
                              └────────────────────┘
```

## What it does

- **Traces all DNS queries** and renders a verdict for each:
  - `VERIFIED` — observed answer matches the on-chain record (trustworthy)
  - `FORGED` — observed answer disagrees with the ledger → **spoof/poison, blocked**
  - `NXDOMAIN` — domain not registered on-chain
  - `FALLBACK` — non-`.chain` domain resolved by upstream DNS (unverifiable)
- **Anchors trust in a blockchain.** Every record operation is a hash-linked
  block. The ledger — not any cache or resolver — is the single source of truth.
- **Detects ledger tampering.** A full integrity scan recomputes every block
  hash and verifies the linkage. Mutating, inserting, deleting, or reordering
  any block is caught and pinpointed.
- **Live dashboard** over WebSocket: query feed, threat console, ledger view,
  integrity status, and one-click attack simulators.

## Run it

```bash
cd soc/backend
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
# open http://127.0.0.1:8000
```

The backend serves the dashboard at `/` and seeds the ledger with sample
domains. No real Ethereum node is required — the ledger is a self-contained,
hash-linked chain. (To wire it to the real `DNSRegistry.sol` contract, point
the original `resolver/resolver.py` at your chain and feed its lookups into
`/api/query`.)

## Prove detection works

Run the test suite — it exercises five attack classes and asserts each is caught:

```bash
cd soc/tests
python test_tamper_detection.py        # readable report
# or
pytest test_tamper_detection.py -v
```

| Check | What it proves |
|-------|----------------|
| Clean chain valid | Control — untouched ledger verifies |
| Content tamper | Mutating a block's value breaks its own hash |
| Sophisticated tamper | Even if the attacker re-mines the block, the **next** block's linkage breaks |
| Block deletion | Removing history breaks the successor's `previous_hash` |
| DNS spoof | A forged answer vs the ledger is flagged `FORGED` |

You can also drive the attacks live from the dashboard buttons, or via the API:

```bash
# Forge a DNS answer for a legit domain → caught as FORGED
curl -X POST localhost:8000/api/simulate/spoof \
  -H 'Content-Type: application/json' \
  -d '{"domain":"bank.chain","forged_value":"6.6.6.6"}'

# Mutate a committed block → caught by the integrity scan
curl -X POST localhost:8000/api/simulate/tamper \
  -H 'Content-Type: application/json' -d '{"new_value":"6.6.6.6"}'

# Re-scan the whole ledger
curl localhost:8000/api/integrity
```

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | SOC dashboard |
| GET | `/api/stats` | Counters (total / verified / forged / fallback / height) |
| GET | `/api/events?limit=N` | Recent trace events |
| GET | `/api/threats?limit=N` | Forged-response events only |
| GET | `/api/chain` | Full ledger snapshot |
| GET | `/api/domains` | Current domain → value table |
| GET | `/api/integrity` | Run an integrity scan, return any breaks |
| POST | `/api/query` | Trace one query `{domain, observed_value, source_ip}` |
| POST | `/api/simulate/spoof` | Inject a forged answer |
| POST | `/api/simulate/tamper` | Mutate a committed block |
| POST | `/api/simulate/traffic?count=N` | Generate benign + stray load |
| WS | `/ws` | Live feed: `trace`, `stats`, `integrity`, `alert` |

## Why tampering can't hide

Each block's hash covers its contents **and** the previous block's hash:

```
hash(block_i) = sha256(index, timestamp, op, domain, value, owner, prev_hash, nonce)
block_{i+1}.previous_hash == hash(block_i)
```

Change any field in block *i* and its recomputed hash no longer matches the
stored one (`CONTENT_TAMPERED`). Re-mine block *i* to fix that, and now
block *i+1* still points at the old hash (`LINKAGE_BROKEN`). To hide the change
you'd have to re-mine every subsequent block faster than the honest network —
which is exactly the work proof-of-work makes infeasible.

## Files

```
soc/
├── backend/
│   ├── app.py          # FastAPI server, REST + WebSocket, attack simulators
│   ├── blockchain.py   # hash-linked ledger + integrity verification
│   ├── tracer.py       # query tracer + forgery verdict engine
│   └── requirements.txt
├── frontend/
│   └── index.html      # SOC dashboard (served at /)
└── tests/
    └── test_tamper_detection.py   # proof that manipulation is detected
```
