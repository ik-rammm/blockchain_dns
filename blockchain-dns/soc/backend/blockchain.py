#!/usr/bin/env python3
"""
blockchain.py — Hash-linked DNS ledger with tamper detection
=============================================================

This module implements the trust anchor for the SOC platform. Every DNS
record operation (domain registration or record update) is committed as a
*block* in an append-only, hash-linked chain. Each block's hash is computed
over its contents PLUS the previous block's hash, so any change to historical
data breaks the cryptographic linkage for that block and every block after it.

The SOC uses two independent integrity checks:

  1. Per-block hash check  — recompute sha256(block contents) and compare to
     the stored hash. Detects mutation of a block's own fields.
  2. Linkage check         — verify block[i].previous_hash == block[i-1].hash.
     Detects insertion, deletion, or reordering of blocks.

If either check fails, `verify_chain()` reports the exact block index and the
nature of the break. This is what makes on-chain DNS "spoof-proof": a forged
record cannot be slipped into history without detection.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ───────────────────────────────────────────────────────────────────────────
# Block
# ───────────────────────────────────────────────────────────────────────────

@dataclass
class Block:
    index: int
    timestamp: float
    operation: str            # "REGISTER" | "UPDATE" | "TRANSFER" | "GENESIS"
    domain: str
    record_value: str         # the IP / hostname / payload being committed
    owner: str                # wallet address that authorized the change
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        """Deterministic sha256 over the canonical block payload."""
        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "operation": self.operation,
                "domain": self.domain,
                "record_value": self.record_value,
                "owner": self.owner,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


# ───────────────────────────────────────────────────────────────────────────
# Integrity report
# ───────────────────────────────────────────────────────────────────────────

@dataclass
class IntegrityReport:
    valid: bool
    checked_blocks: int
    breaks: list[dict] = field(default_factory=list)
    verified_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


# ───────────────────────────────────────────────────────────────────────────
# Blockchain
# ───────────────────────────────────────────────────────────────────────────

class Blockchain:
    """
    Minimal proof-of-work-flavoured hash-linked ledger.

    `difficulty` controls how many leading zeros a block hash must have. It's
    kept low (default 2) so the demo mines instantly while still exercising the
    nonce/mining path that a real chain would use.
    """

    def __init__(self, difficulty: int = 2):
        self.difficulty = difficulty
        self.chain: list[Block] = []
        self._create_genesis()
        # Fast lookup of the latest authoritative value per domain.
        self._latest: dict[str, str] = {}

    # ── Construction ──────────────────────────────────────────────────────

    def _create_genesis(self) -> None:
        genesis = Block(
            index=0,
            timestamp=time.time(),
            operation="GENESIS",
            domain="",
            record_value="",
            owner="0x0000000000000000000000000000000000000000",
            previous_hash="0" * 64,
        )
        genesis.hash = self._mine(genesis)
        self.chain.append(genesis)

    def _mine(self, block: Block) -> str:
        """Find a nonce so the hash starts with `difficulty` zeros."""
        prefix = "0" * self.difficulty
        block.nonce = 0
        h = block.compute_hash()
        while not h.startswith(prefix):
            block.nonce += 1
            h = block.compute_hash()
        return h

    # ── Commit operations ─────────────────────────────────────────────────

    def commit(
        self,
        operation: str,
        domain: str,
        record_value: str,
        owner: str,
    ) -> Block:
        """Append a new authorized DNS operation to the chain."""
        prev = self.chain[-1]
        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            operation=operation,
            domain=domain,
            record_value=record_value,
            owner=owner,
            previous_hash=prev.hash,
        )
        block.hash = self._mine(block)
        self.chain.append(block)
        self._latest[domain] = record_value
        return block

    # ── Authoritative resolution ──────────────────────────────────────────

    def resolve(self, domain: str) -> Optional[str]:
        """
        Return the authoritative (most recent) on-chain value for a domain,
        derived by replaying the chain — NOT from a mutable cache. This is the
        ground truth the SOC compares observed DNS responses against.
        """
        value = None
        for block in self.chain:
            if block.domain == domain and block.operation in ("REGISTER", "UPDATE"):
                value = block.record_value
        return value

    def domains(self) -> dict[str, str]:
        """Replay the chain to build the current domain → value table."""
        table: dict[str, str] = {}
        for block in self.chain:
            if block.domain and block.operation in ("REGISTER", "UPDATE"):
                table[block.domain] = block.record_value
        return table

    # ── Integrity verification (the heart of tamper detection) ────────────

    def verify_chain(self) -> IntegrityReport:
        """
        Walk the entire chain and prove its integrity.

        Detects:
          • mutated block contents      (per-block hash mismatch)
          • broken linkage              (previous_hash != prior block hash)
          • invalid proof-of-work       (hash doesn't meet difficulty)
        """
        breaks: list[dict] = []
        prefix = "0" * self.difficulty

        for i, block in enumerate(self.chain):
            # 1. Recompute this block's hash from its current contents.
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                breaks.append({
                    "index": block.index,
                    "domain": block.domain,
                    "type": "CONTENT_TAMPERED",
                    "detail": "Stored hash does not match recomputed hash — "
                              "block contents were altered after mining.",
                    "stored_hash": block.hash,
                    "recomputed_hash": recomputed,
                })

            # 2. Proof-of-work check (skip genesis is fine; it was mined too).
            if not block.hash.startswith(prefix):
                breaks.append({
                    "index": block.index,
                    "domain": block.domain,
                    "type": "INVALID_POW",
                    "detail": f"Hash does not satisfy difficulty {self.difficulty}.",
                })

            # 3. Linkage check (every block except genesis).
            if i > 0:
                prev = self.chain[i - 1]
                if block.previous_hash != prev.hash:
                    breaks.append({
                        "index": block.index,
                        "domain": block.domain,
                        "type": "LINKAGE_BROKEN",
                        "detail": "previous_hash does not match the prior block's "
                                  "hash — a block was inserted, removed, or reordered.",
                        "expected_previous": prev.hash,
                        "found_previous": block.previous_hash,
                    })

        return IntegrityReport(
            valid=len(breaks) == 0,
            checked_blocks=len(self.chain),
            breaks=breaks,
        )

    # ── Snapshot for the dashboard ────────────────────────────────────────

    def snapshot(self) -> list[dict]:
        return [b.to_dict() for b in self.chain]

    def height(self) -> int:
        return len(self.chain)
