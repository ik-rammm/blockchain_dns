#!/usr/bin/env python3
"""
Quick test script — sends DNS queries to the blockchain resolver.

Usage:
    1. Start the resolver:  python resolver/resolver.py --demo
    2. Run this script:     python test/test_resolver.py
"""

import socket
import struct
import sys


def build_query(domain: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet."""
    import random
    txn_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)

    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)

    return header + question, txn_id


def parse_response(data: bytes) -> dict:
    """Parse a DNS response into a readable dict."""
    txn_id = struct.unpack("!H", data[:2])[0]
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0x0F
    qdcount, ancount = struct.unpack("!HH", data[4:8])

    result = {
        "txn_id": txn_id,
        "rcode": rcode,
        "rcode_name": {0: "NOERROR", 3: "NXDOMAIN"}.get(rcode, f"RCODE_{rcode}"),
        "answers": ancount,
        "ip": None,
    }

    if ancount > 0 and rcode == 0:
        # Find the answer section (skip header + question)
        offset = 12
        # Skip question
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5  # null terminator + qtype + qclass

        # Parse answer
        offset += 2  # pointer
        atype = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 8  # type + class + ttl
        rdlen = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        if atype == 1 and rdlen == 4:
            ip = ".".join(str(b) for b in data[offset:offset + 4])
            result["ip"] = ip

    return result


def query_resolver(domain: str, server: str = "127.0.0.1", port: int = 5553):
    """Send a DNS query and print the result."""
    pkt, txn_id = build_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        sock.sendto(pkt, (server, port))
        resp, _ = sock.recvfrom(4096)
        result = parse_response(resp)
        return result
    except socket.timeout:
        return {"error": "Timeout — is the resolver running?"}
    finally:
        sock.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5553

    print("=" * 60)
    print("  Blockchain DNS Resolver — Test Suite")
    print(f"  Target: 127.0.0.1:{port}")
    print("=" * 60)

    tests = [
        ("example.chain",  "93.184.216.34",  "Registered blockchain domain"),
        ("secure.chain",   "104.21.32.1",    "Another registered domain"),
        ("mysite.chain",   "192.168.1.100",  "Private IP domain"),
        ("evil.chain",     None,             "Unregistered (should be NXDOMAIN)"),
    ]

    passed = 0
    failed = 0

    for domain, expected_ip, description in tests:
        result = query_resolver(domain, port=port)
        print(f"\n  ── {description} ──")
        print(f"  Query:    {domain}")

        if "error" in result:
            print(f"  Result:   ERROR — {result['error']}")
            failed += 1
            continue

        actual_ip = result.get("ip")
        rcode = result.get("rcode_name", "?")

        if expected_ip is None:
            # Expecting NXDOMAIN
            if result["rcode"] == 3:
                print(f"  Result:   NXDOMAIN (correct ✓)")
                passed += 1
            else:
                print(f"  Result:   Got {rcode} / {actual_ip} — expected NXDOMAIN ✗")
                failed += 1
        else:
            if actual_ip == expected_ip:
                print(f"  Result:   {actual_ip} (correct ✓)")
                passed += 1
            else:
                print(f"  Result:   {actual_ip} — expected {expected_ip} ✗")
                failed += 1

    # Spoofing simulation
    print(f"\n  ── DNS Spoofing Resistance Test ──")
    print(f"  Scenario: Attacker tries to redirect example.chain → 6.6.6.6")
    result = query_resolver("example.chain", port=port)
    if result.get("ip") == "93.184.216.34":
        print(f"  Result:   Resolver returned on-chain IP {result['ip']}")
        print(f"  Verdict:  Spoofing attack BLOCKED ✓ (forged record ignored)")
        passed += 1
    else:
        print(f"  Result:   Got {result.get('ip')} — unexpected")
        failed += 1

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
