#!/usr/bin/env python3
"""
Blockchain DNS Resolver
=======================
A local DNS proxy that intercepts queries, checks the blockchain registry first,
and falls back to traditional DNS for unregistered domains.

Usage:
    python resolver.py --rpc-url http://127.0.0.1:8545 --contract 0x... [--port 5553]

The resolver:
  1. Listens for standard DNS queries on UDP (default port 5553).
  2. Looks up the domain in the on-chain DNSRegistry smart contract.
  3. If found and not expired, returns the on-chain record (spoofing-proof).
  4. If not found, forwards the query to a traditional upstream resolver (8.8.8.8).
  5. Caches results locally with TTL-based expiry for performance.
"""

import argparse
import json
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional dependency imports (graceful fallback for demo purposes)
# ---------------------------------------------------------------------------
try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("blockchain-dns")


# ═══════════════════════════════════════════════════════════════════════════
# ABI (trimmed to read functions the resolver needs)
# ═══════════════════════════════════════════════════════════════════════════

CONTRACT_ABI = json.loads("""
[
  {
    "inputs": [{"internalType": "string", "name": "name", "type": "string"}],
    "name": "resolveDomain",
    "outputs": [
      {"internalType": "string",  "name": "ip",        "type": "string"},
      {"internalType": "address", "name": "owner",     "type": "address"},
      {"internalType": "uint256", "name": "expiresAt", "type": "uint256"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "string", "name": "name", "type": "string"}],
    "name": "isAvailable",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "string", "name": "name", "type": "string"}],
    "name": "getAllRecords",
    "outputs": [
      {"internalType": "string[]",  "name": "values",      "type": "string[]"},
      {"internalType": "uint8[]",   "name": "recordTypes",  "type": "uint8[]"},
      {"internalType": "uint256[]", "name": "ttls",         "type": "uint256[]"},
      {"internalType": "uint256[]", "name": "updatedAts",   "type": "uint256[]"}
    ],
    "stateMutability": "view",
    "type": "function"
  }
]
""")


# ═══════════════════════════════════════════════════════════════════════════
# Cache
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CacheEntry:
    ip: str
    owner: str
    expires_at: int
    cached_at: float
    ttl: int  # seconds

    def is_expired(self) -> bool:
        return time.time() - self.cached_at > self.ttl


class DNSCache:
    """Thread-safe LRU-ish cache with TTL expiry."""

    def __init__(self, max_size: int = 1024):
        self._store: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self._max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, domain: str) -> Optional[CacheEntry]:
        with self._lock:
            entry = self._store.get(domain)
            if entry and not entry.is_expired():
                self.hits += 1
                return entry
            if entry:
                del self._store[domain]
            self.misses += 1
            return None

    def put(self, domain: str, entry: CacheEntry) -> None:
        with self._lock:
            if len(self._store) >= self._max_size:
                oldest_key = min(self._store, key=lambda k: self._store[k].cached_at)
                del self._store[oldest_key]
            self._store[domain] = entry

    def invalidate(self, domain: str) -> None:
        with self._lock:
            self._store.pop(domain, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "size": len(self._store),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": f"{self.hits / max(1, self.hits + self.misses) * 100:.1f}%",
            }


# ═══════════════════════════════════════════════════════════════════════════
# Blockchain client
# ═══════════════════════════════════════════════════════════════════════════

class BlockchainDNSClient:
    """Wraps Web3 calls to the DNSRegistry contract."""

    def __init__(self, rpc_url: str, contract_address: str):
        if not HAS_WEB3:
            raise RuntimeError(
                "web3 package not installed. Run: pip install web3"
            )
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC at {rpc_url}")

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=CONTRACT_ABI,
        )
        log.info("Connected to chain (ID %s) — contract %s",
                 self.w3.eth.chain_id, contract_address)

    def resolve(self, domain: str) -> Optional[tuple[str, str, int]]:
        """Returns (ip, owner, expiresAt) or None if not registered / expired."""
        try:
            available = self.contract.functions.isAvailable(domain).call()
            if available:
                return None
            ip, owner, expires_at = self.contract.functions.resolveDomain(domain).call()
            return ip, owner, expires_at
        except Exception as exc:
            log.debug("Chain lookup failed for %s: %s", domain, exc)
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Minimal DNS packet parser / builder (no dnslib dependency needed)
# ═══════════════════════════════════════════════════════════════════════════

QTYPE_A = 1
QTYPE_AAAA = 28

def parse_dns_query(data: bytes) -> tuple[int, str, int]:
    """Parse a raw DNS query → (transaction_id, domain_name, qtype)."""
    txn_id = struct.unpack("!H", data[:2])[0]
    # skip header (12 bytes), walk the question section
    offset = 12
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode())
        offset += length
    domain = ".".join(labels)
    qtype = struct.unpack("!H", data[offset:offset + 2])[0]
    return txn_id, domain, qtype


def build_dns_response(txn_id: int, domain: str, ip: str, ttl: int = 300) -> bytes:
    """Build a minimal DNS A-record response packet."""
    # Header
    header = struct.pack("!HHHHHH",
        txn_id,
        0x8180,  # flags: response, authoritative, recursion available
        1,       # questions
        1,       # answers
        0, 0,
    )
    # Question section (echo the query)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", QTYPE_A, 1)  # type A, class IN

    # Answer section
    answer = b"\xc0\x0c"  # pointer to domain in question
    answer += struct.pack("!HH", QTYPE_A, 1)
    answer += struct.pack("!I", ttl)
    octets = [int(o) for o in ip.split(".")]
    answer += struct.pack("!H", 4)
    answer += bytes(octets)

    return header + question + answer


def build_dns_nxdomain(txn_id: int, domain: str) -> bytes:
    """Build a DNS NXDOMAIN (not found) response."""
    header = struct.pack("!HHHHHH",
        txn_id,
        0x8183,  # flags: response + NXDOMAIN rcode
        1, 0, 0, 0,
    )
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", QTYPE_A, 1)
    return header + question


# ═══════════════════════════════════════════════════════════════════════════
# Traditional DNS forwarder (fallback)
# ═══════════════════════════════════════════════════════════════════════════

def forward_to_upstream(data: bytes, upstream: str = "8.8.8.8", port: int = 53) -> bytes:
    """Forward a raw DNS query to a traditional upstream resolver."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(data, (upstream, port))
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        log.warning("Upstream DNS timeout (%s:%d)", upstream, port)
        return b""
    finally:
        sock.close()


# ═══════════════════════════════════════════════════════════════════════════
# DNS Server
# ═══════════════════════════════════════════════════════════════════════════

class BlockchainDNSServer:
    """
    UDP DNS server that resolves .chain domains from the blockchain
    and everything else via traditional DNS.
    """

    BLOCKCHAIN_SUFFIX = ".chain"

    def __init__(
        self,
        blockchain_client: Optional[BlockchainDNSClient],
        host: str = "0.0.0.0",
        port: int = 5553,
        upstream: str = "8.8.8.8",
        cache_ttl: int = 300,
    ):
        self.client = blockchain_client
        self.host = host
        self.port = port
        self.upstream = upstream
        self.default_ttl = cache_ttl
        self.cache = DNSCache()
        self._running = False

    def handle_query(self, data: bytes, addr: tuple) -> bytes:
        try:
            txn_id, domain, qtype = parse_dns_query(data)
        except Exception:
            log.error("Malformed DNS query from %s", addr)
            return b""

        log.info("Query  %-6s  %s  from %s", "A" if qtype == QTYPE_A else str(qtype), domain, addr)

        # ── Blockchain path ──────────────────────────────────────────
        if domain.endswith(self.BLOCKCHAIN_SUFFIX):
            # Check cache first
            cached = self.cache.get(domain)
            if cached:
                log.info("Cache  HIT     %s → %s", domain, cached.ip)
                return build_dns_response(txn_id, domain, cached.ip, self.default_ttl)

            # Query blockchain
            if self.client:
                result = self.client.resolve(domain)
                if result:
                    ip, owner, expires_at = result
                    self.cache.put(domain, CacheEntry(
                        ip=ip, owner=owner, expires_at=expires_at,
                        cached_at=time.time(), ttl=self.default_ttl,
                    ))
                    log.info("Chain  FOUND   %s → %s  (owner %s)", domain, ip, owner[:10] + "…")
                    return build_dns_response(txn_id, domain, ip, self.default_ttl)

            log.info("Chain  MISS    %s — not registered", domain)
            return build_dns_nxdomain(txn_id, domain)

        # ── Traditional DNS fallback ─────────────────────────────────
        log.info("Fwd    UPSTREAM  %s → %s", domain, self.upstream)
        return forward_to_upstream(data, self.upstream)

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        self._running = True

        log.info("═" * 60)
        log.info("  Blockchain DNS Resolver")
        log.info("  Listening on %s:%d", self.host, self.port)
        log.info("  Blockchain suffix: %s", self.BLOCKCHAIN_SUFFIX)
        log.info("  Upstream fallback: %s", self.upstream)
        log.info("═" * 60)

        try:
            while self._running:
                data, addr = sock.recvfrom(4096)
                # Handle each query in a thread to avoid blocking
                thread = threading.Thread(
                    target=self._handle_and_reply,
                    args=(sock, data, addr),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            log.info("Shutting down…")
        finally:
            sock.close()

    def _handle_and_reply(self, sock: socket.socket, data: bytes, addr: tuple) -> None:
        response = self.handle_query(data, addr)
        if response:
            sock.sendto(response, addr)

    def stop(self) -> None:
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# Standalone demo mode (no blockchain connection required)
# ═══════════════════════════════════════════════════════════════════════════

class MockBlockchainClient:
    """
    Simulated on-chain registry for demo / testing without a real chain.
    Pre-loaded with sample domains.
    """

    def __init__(self):
        self.registry: dict[str, tuple[str, str, int]] = {
            "example.chain":  ("93.184.216.34",  "0xABCD1234abcd1234abcd1234abcd1234abcd1234", 9999999999),
            "secure.chain":   ("104.21.32.1",    "0x1111222233334444555566667777888899990000", 9999999999),
            "mysite.chain":   ("192.168.1.100",   "0xDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEF", 9999999999),
            "blockdns.chain": ("10.0.0.42",       "0xCAFEBABEcafebabe0000000000000000cafebabe", 9999999999),
        }
        log.info("MockBlockchain loaded with %d domains", len(self.registry))

    def resolve(self, domain: str) -> Optional[tuple[str, str, int]]:
        return self.registry.get(domain)

    def register(self, domain: str, ip: str, owner: str) -> None:
        self.registry[domain] = (ip, owner, 9999999999)
        log.info("MockBlockchain: registered %s → %s", domain, ip)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Blockchain DNS Resolver — spoof-proof domain resolution"
    )
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545",
                        help="Ethereum JSON-RPC endpoint")
    parser.add_argument("--contract", default=None,
                        help="DNSRegistry contract address")
    parser.add_argument("--port", type=int, default=5553,
                        help="UDP port to listen on (default 5553)")
    parser.add_argument("--upstream", default="8.8.8.8",
                        help="Upstream DNS for non-blockchain domains")
    parser.add_argument("--cache-ttl", type=int, default=300,
                        help="Cache TTL in seconds (default 300)")
    parser.add_argument("--demo", action="store_true",
                        help="Run with mock blockchain (no chain needed)")
    args = parser.parse_args()

    if args.demo:
        log.info("Starting in DEMO mode (mock blockchain)")
        client = MockBlockchainClient()
    elif args.contract:
        client = BlockchainDNSClient(args.rpc_url, args.contract)
    else:
        log.warning("No --contract supplied and --demo not set. Running without chain.")
        client = MockBlockchainClient()

    server = BlockchainDNSServer(
        blockchain_client=client,
        port=args.port,
        upstream=args.upstream,
        cache_ttl=args.cache_ttl,
    )
    server.start()


if __name__ == "__main__":
    main()
