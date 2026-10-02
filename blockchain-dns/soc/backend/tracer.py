#!/usr/bin/env python3
"""
tracer.py — DNS query tracer & forgery detector
================================================

The SOC sits in the resolution path and traces every DNS query. For each
query it records:

  • the domain asked for
  • the answer that was *observed* on the wire (what a resolver returned)
  • the *authoritative* value from the blockchain ledger
  • a verdict

Verdicts
--------
  VERIFIED   — observed answer matches the on-chain record. Trustworthy.
  FORGED     — observed answer DIFFERS from the on-chain record. This is the
               signature of DNS spoofing / cache poisoning / a hijack. BLOCKED.
  NXDOMAIN   — domain is not on-chain and has no answer.
  FALLBACK   — non-.chain domain; resolved by traditional upstream DNS and
               therefore NOT protected by the ledger (flagged as unverifiable).

The detector never trusts the observed answer on its own. The blockchain is
the single source of truth; anything that disagrees with it is treated as an
attack regardless of how "valid" the DNS packet looks.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from blockchain import Blockchain


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    FORGED = "FORGED"
    NXDOMAIN = "NXDOMAIN"
    FALLBACK = "FALLBACK"


@dataclass
class TraceEvent:
    id: str
    timestamp: float
    domain: str
    qtype: str
    source_ip: str
    observed_value: Optional[str]
    onchain_value: Optional[str]
    verdict: str
    detail: str
    latency_ms: float

    def to_dict(self) -> dict:
        return asdict(self)


class DNSTracer:
    """
    Traces queries and decides a verdict by comparing the observed answer to
    the authoritative on-chain value. Keeps an in-memory ring buffer of recent
    events plus running counters for the SOC dashboard.
    """

    BLOCKCHAIN_SUFFIX = ".chain"

    def __init__(self, chain: Blockchain, history: int = 500):
        self.chain = chain
        self._events: list[TraceEvent] = []
        self._history = history
        self.counters = {
            "total": 0,
            "verified": 0,
            "forged": 0,
            "nxdomain": 0,
            "fallback": 0,
        }

    # ── Core trace ────────────────────────────────────────────────────────

    def trace(
        self,
        domain: str,
        observed_value: Optional[str],
        source_ip: str = "127.0.0.1",
        qtype: str = "A",
    ) -> TraceEvent:
        """
        Trace a single resolution.

        `observed_value` is whatever answer was returned on the wire (by a
        resolver, an attacker, or a cache). We compare it to the chain.
        """
        start = time.perf_counter()
        domain = domain.lower().rstrip(".")

        if not domain.endswith(self.BLOCKCHAIN_SUFFIX):
            verdict = Verdict.FALLBACK
            onchain = None
            detail = ("Non-.chain domain resolved by traditional upstream DNS; "
                      "NOT protected by the ledger — treat as unverifiable.")
        else:
            onchain = self.chain.resolve(domain)
            if onchain is None:
                verdict = Verdict.NXDOMAIN
                detail = "Domain is not registered on-chain. No authoritative record."
            elif observed_value is None:
                # We have a truth but saw no answer — report the truth.
                verdict = Verdict.VERIFIED
                detail = "Served authoritative on-chain record."
                observed_value = onchain
            elif observed_value == onchain:
                verdict = Verdict.VERIFIED
                detail = "Observed answer matches on-chain record. Trustworthy."
            else:
                verdict = Verdict.FORGED
                detail = (f"FORGERY DETECTED: observed {observed_value!r} but the "
                          f"ledger authoritatively says {onchain!r}. Response "
                          f"rejected; serving on-chain value instead.")

        latency = (time.perf_counter() - start) * 1000.0
        event = TraceEvent(
            id=uuid.uuid4().hex[:12],
            timestamp=time.time(),
            domain=domain,
            qtype=qtype,
            source_ip=source_ip,
            observed_value=observed_value,
            onchain_value=onchain,
            verdict=verdict.value,
            detail=detail,
            latency_ms=round(latency, 3),
        )
        self._record(event)
        return event

    def _record(self, event: TraceEvent) -> None:
        self._events.append(event)
        if len(self._events) > self._history:
            self._events.pop(0)
        self.counters["total"] += 1
        self.counters[event.verdict.lower()] += 1

    # ── Accessors for the dashboard ───────────────────────────────────────

    def recent(self, limit: int = 100) -> list[dict]:
        return [e.to_dict() for e in reversed(self._events[-limit:])]

    def threats(self, limit: int = 100) -> list[dict]:
        forged = [e for e in self._events if e.verdict == Verdict.FORGED.value]
        return [e.to_dict() for e in reversed(forged[-limit:])]

    def stats(self) -> dict:
        c = self.counters
        protected = c["verified"] + c["forged"]
        block_rate = (c["forged"] / protected * 100.0) if protected else 0.0
        return {
            **c,
            "blocked_forgeries": c["forged"],
            "forgery_rate_pct": round(block_rate, 2),
            "chain_height": self.chain.height(),
        }
