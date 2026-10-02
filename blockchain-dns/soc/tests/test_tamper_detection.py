#!/usr/bin/env python3
"""
test_tamper_detection.py — proof that manipulation is always detected
=====================================================================

This suite is the evidence the SOC platform actually delivers on its promise:
"nothing is forged, and any manipulation of the blockchain network is detected."

It exercises five attack classes against the hash-linked ledger and the DNS
tracer, and asserts each one is caught:

  1. Clean chain verifies as valid (control).
  2. CONTENT tamper      — mutate a block's record value           → detected.
  3. SOPHISTICATED tamper— mutate AND re-mine the block's own hash  → still
                           detected, because the *next* block's linkage breaks.
  4. DELETION / reorder  — remove a block from history             → detected.
  5. DNS SPOOF           — forged answer vs on-chain truth          → FORGED.

Run directly for a readable report:
    python test_tamper_detection.py

Or with pytest:
    pytest test_tamper_detection.py -v
"""

from __future__ import annotations

import os
import sys

# Make the backend importable whether run from tests/ or project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from blockchain import Blockchain          # noqa: E402
from tracer import DNSTracer, Verdict       # noqa: E402


# ───────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ───────────────────────────────────────────────────────────────────────────

def build_chain() -> Blockchain:
    bc = Blockchain(difficulty=2)
    bc.commit("REGISTER", "bank.chain", "203.0.113.10", "0xOWNER_BANK")
    bc.commit("REGISTER", "example.chain", "93.184.216.34", "0xOWNER_EX")
    bc.commit("UPDATE",   "bank.chain", "203.0.113.11", "0xOWNER_BANK")  # legit update
    return bc


def _find_break(report, btype, index):
    return any(b["type"] == btype and b["index"] == index for b in report.breaks)


# ───────────────────────────────────────────────────────────────────────────
# Tests
# ───────────────────────────────────────────────────────────────────────────

def test_clean_chain_is_valid():
    """Control: an untouched chain must verify cleanly."""
    bc = build_chain()
    report = bc.verify_chain()
    assert report.valid is True
    assert report.breaks == []
    assert report.checked_blocks == bc.height()


def test_content_tamper_is_detected():
    """Mutating a block's record value (no re-mine) breaks its own hash."""
    bc = build_chain()
    assert bc.verify_chain().valid is True

    # Attacker rewrites bank.chain's IP directly in block #1.
    target = bc.chain[1]
    target.record_value = "6.6.6.6"          # malicious IP, hash NOT updated

    report = bc.verify_chain()
    assert report.valid is False
    assert _find_break(report, "CONTENT_TAMPERED", 1)


def test_sophisticated_tamper_is_still_detected():
    """
    A smarter attacker mutates the block AND re-mines its hash so the per-block
    check passes. But they cannot also re-mine every following block (that's the
    whole point of proof-of-work + linkage), so the NEXT block's previous_hash
    no longer matches → the chain still fails verification.
    """
    bc = build_chain()
    target = bc.chain[1]

    # Mutate and recompute a valid PoW hash for THIS block only.
    target.record_value = "6.6.6.6"
    target.hash = bc._mine(target)           # block #1 now self-consistent

    report = bc.verify_chain()
    # Block #1 itself looks fine now...
    assert not _find_break(report, "CONTENT_TAMPERED", 1)
    # ...but block #2 still points at the OLD hash → linkage broken.
    assert report.valid is False
    assert _find_break(report, "LINKAGE_BROKEN", 2)


def test_block_deletion_is_detected():
    """Removing a historical block breaks the linkage of its successor."""
    bc = build_chain()
    # Chain layout: [0]genesis, [1]bank REGISTER, [2]example REGISTER, [3]bank UPDATE.
    removed = bc.chain.pop(2)                 # drop a middle block from history
    assert removed.domain == "example.chain"

    report = bc.verify_chain()
    assert report.valid is False
    # The successor block's previous_hash now points at a block that is no
    # longer its predecessor → linkage break exposes the deletion.
    assert any(b["type"] == "LINKAGE_BROKEN" for b in report.breaks)


def test_dns_spoof_is_detected_as_forged():
    """A forged DNS answer that disagrees with the ledger is flagged FORGED."""
    bc = build_chain()
    tracer = DNSTracer(bc)

    truth = bc.resolve("bank.chain")          # latest authoritative value
    assert truth == "203.0.113.11"

    # Honest resolution → VERIFIED.
    ok = tracer.trace("bank.chain", observed_value=truth, source_ip="10.0.0.5")
    assert ok.verdict == Verdict.VERIFIED.value

    # Attacker injects a forged IP → FORGED, response rejected.
    spoof = tracer.trace("bank.chain", observed_value="6.6.6.6", source_ip="10.13.37.66")
    assert spoof.verdict == Verdict.FORGED.value
    assert spoof.onchain_value == truth
    assert "FORGERY DETECTED" in spoof.detail


def test_unregistered_domain_is_nxdomain():
    bc = build_chain()
    tracer = DNSTracer(bc)
    ev = tracer.trace("ghost.chain", observed_value="1.2.3.4")
    assert ev.verdict == Verdict.NXDOMAIN.value


def test_non_chain_domain_is_fallback_unverifiable():
    bc = build_chain()
    tracer = DNSTracer(bc)
    ev = tracer.trace("google.com", observed_value=None)
    assert ev.verdict == Verdict.FALLBACK.value


# ───────────────────────────────────────────────────────────────────────────
# Readable standalone runner
# ───────────────────────────────────────────────────────────────────────────

def _run_report():
    line = "═" * 68
    print(line)
    print("  BLOCKCHAIN DNS — TAMPER DETECTION PROOF")
    print(line)

    tests = [
        ("Clean chain verifies as valid (control)", test_clean_chain_is_valid),
        ("Content tamper is detected", test_content_tamper_is_detected),
        ("Sophisticated tamper (re-mined) still detected via linkage",
         test_sophisticated_tamper_is_still_detected),
        ("Block deletion / reorder is detected", test_block_deletion_is_detected),
        ("DNS spoof flagged as FORGED", test_dns_spoof_is_detected_as_forged),
        ("Unregistered .chain domain → NXDOMAIN", test_unregistered_domain_is_nxdomain),
        ("Non-.chain domain → FALLBACK (unverifiable)",
         test_non_chain_domain_is_fallback_unverifiable),
    ]

    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS]  {name}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL]  {name}  — {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  [ERROR] {name}  — {type(e).__name__}: {e}")

    print(line)
    print(f"  RESULT: {passed}/{len(tests)} checks passed")
    print(line)

    # Live demo of a detected tamper, with the integrity report.
    print("\n  DEMO — mutating a committed block and scanning the ledger:\n")
    bc = build_chain()
    print(f"    Before:  bank.chain → {bc.resolve('bank.chain')}  (chain valid: {bc.verify_chain().valid})")
    bc.chain[1].record_value = "6.6.6.6"   # tamper, no re-mine
    rpt = bc.verify_chain()
    print(f"    After tamper of block #1 (no re-mine):  chain valid: {rpt.valid}")
    for b in rpt.breaks:
        print(f"      → block #{b['index']}  {b['type']}: {b['detail']}")
    print()
    return passed == len(tests)


if __name__ == "__main__":
    ok = _run_report()
    sys.exit(0 if ok else 1)
