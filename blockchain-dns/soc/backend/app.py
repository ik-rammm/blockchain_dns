#!/usr/bin/env python3
"""
app.py — Blockchain DNS SOC platform (backend)
==============================================

A FastAPI service that powers a Security Operations Center for blockchain DNS:

  • Maintains the hash-linked ledger (blockchain.py) as the source of truth.
  • Traces every DNS query and renders a verdict (tracer.py).
  • Streams live trace + integrity events to the dashboard over WebSocket.
  • Exposes attack simulators so operators can prove detection works:
        POST /api/simulate/spoof   — inject a forged DNS answer  → caught as FORGED
        POST /api/simulate/tamper  — mutate a committed block    → caught by integrity scan
        POST /api/simulate/traffic — generate benign query load
  • Serves the single-page dashboard at /.

Run:
    pip install -r requirements.txt
    uvicorn app:app --reload --port 8000
    # open http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from blockchain import Blockchain
from tracer import DNSTracer

# ───────────────────────────────────────────────────────────────────────────
# App state
# ───────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Blockchain DNS SOC", version="1.0.0")

chain = Blockchain(difficulty=2)
tracer = DNSTracer(chain)

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

# Seed the ledger with authoritative domains (mirrors the resolver demo set).
SEED = {
    "example.chain":  ("93.184.216.34",  "0xABCD1234abcd1234abcd1234abcd1234abcd1234"),
    "secure.chain":   ("104.21.32.1",    "0x1111222233334444555566667777888899990000"),
    "mysite.chain":   ("192.168.1.100",  "0xDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEF"),
    "blockdns.chain": ("10.0.0.42",       "0xCAFEBABEcafebabe0000000000000000cafebabe"),
    "bank.chain":     ("203.0.113.10",    "0xBA17BA17BA17BA17BA17BA17BA17BA17BA17BA17"),
}
for _name, (_ip, _owner) in SEED.items():
    chain.commit("REGISTER", _name, _ip, _owner)


# ───────────────────────────────────────────────────────────────────────────
# WebSocket connection manager (live SOC feed)
# ───────────────────────────────────────────────────────────────────────────

class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


hub = Hub()


async def emit(kind: str, payload: dict):
    await hub.broadcast({"kind": kind, "payload": payload})


# ───────────────────────────────────────────────────────────────────────────
# Request models
# ───────────────────────────────────────────────────────────────────────────

class QueryIn(BaseModel):
    domain: str
    observed_value: str | None = None
    source_ip: str = "127.0.0.1"
    qtype: str = "A"


class SpoofIn(BaseModel):
    domain: str = "bank.chain"
    forged_value: str = "6.6.6.6"
    source_ip: str = "10.13.37.66"


class TamperIn(BaseModel):
    block_index: int | None = None
    new_value: str = "6.6.6.6"


# ───────────────────────────────────────────────────────────────────────────
# Dashboard
# ───────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    if FRONTEND.exists():
        return FRONTEND.read_text(encoding="utf-8", errors="replace")
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


# ───────────────────────────────────────────────────────────────────────────
# REST API
# ───────────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    return tracer.stats()


@app.get("/api/events")
async def get_events(limit: int = 100):
    return tracer.recent(limit)


@app.get("/api/threats")
async def get_threats(limit: int = 100):
    return tracer.threats(limit)


@app.get("/api/chain")
async def get_chain():
    return {"height": chain.height(), "blocks": chain.snapshot()}


@app.get("/api/domains")
async def get_domains():
    return chain.domains()


@app.get("/api/integrity")
async def get_integrity():
    """Run a full integrity scan over the ledger and report any tampering."""
    report = chain.verify_chain().to_dict()
    await emit("integrity", report)
    return report


@app.post("/api/query")
async def post_query(q: QueryIn):
    event = tracer.trace(q.domain, q.observed_value, q.source_ip, q.qtype)
    await emit("trace", event.to_dict())
    await emit("stats", tracer.stats())
    return event.to_dict()


# ── Attack simulators ──────────────────────────────────────────────────────

@app.post("/api/simulate/spoof")
async def simulate_spoof(s: SpoofIn):
    """
    Simulate a DNS spoofing / cache-poisoning attack: an attacker returns a
    forged IP for a legitimate on-chain domain. The tracer compares it to the
    ledger and must flag it as FORGED.
    """
    event = tracer.trace(s.domain, s.forged_value, s.source_ip, "A")
    await emit("trace", event.to_dict())
    await emit("stats", tracer.stats())
    if event.verdict == "FORGED":
        await emit("alert", event.to_dict())
    return {
        "attack": "dns_spoofing",
        "outcome": event.verdict,
        "detected": event.verdict == "FORGED",
        "event": event.to_dict(),
    }


@app.post("/api/simulate/tamper")
async def simulate_tamper(t: TamperIn):
    """
    Simulate an attacker mutating a committed block (e.g. rewriting a domain's
    IP directly in the ledger). We mutate the block IN PLACE *without*
    re-mining, then run the integrity scan — which must detect the break.
    """
    # Pick a real REGISTER/UPDATE block by default.
    idx = t.block_index
    if idx is None:
        candidates = [b.index for b in chain.chain if b.operation in ("REGISTER", "UPDATE")]
        idx = random.choice(candidates) if candidates else 0

    target = chain.chain[idx]
    before = {
        "domain": target.domain,
        "record_value": target.record_value,
        "stored_hash": target.hash,
    }

    # Mutate the record value but DO NOT recompute/re-mine the hash.
    # This is exactly what a tamperer who lacks consensus power would do.
    target.record_value = t.new_value

    report = chain.verify_chain().to_dict()
    await emit("integrity", report)
    await emit("alert", {
        "verdict": "CHAIN_TAMPERED" if not report["valid"] else "CLEAN",
        "domain": before["domain"],
        "detail": f"Block #{idx} record_value changed "
                  f"{before['record_value']!r} → {t.new_value!r} without re-mining.",
        "block_index": idx,
    })

    return {
        "attack": "ledger_tampering",
        "block_index": idx,
        "before": before,
        "after_value": t.new_value,
        "detected": not report["valid"],
        "integrity": report,
    }


@app.post("/api/simulate/traffic")
async def simulate_traffic(count: int = 12):
    """Generate a burst of mostly-benign DNS queries to populate the feed."""
    domains = list(chain.domains().keys()) + ["google.com", "github.com", "unregistered.chain"]
    sources = ["10.0.0.5", "10.0.0.9", "192.168.1.40", "172.16.0.3", "127.0.0.1"]
    out = []
    for _ in range(max(1, min(count, 50))):
        dom = random.choice(domains)
        truth = chain.resolve(dom)
        # Mostly honest; occasionally a forged answer sneaks in.
        if truth and random.random() < 0.15:
            observed = "13.37.13.37"  # forged
        elif dom.endswith(".chain"):
            observed = truth
        else:
            observed = None  # upstream fallback
        ev = tracer.trace(dom, observed, random.choice(sources))
        out.append(ev.to_dict())
        await emit("trace", ev.to_dict())
        if ev.verdict == "FORGED":
            await emit("alert", ev.to_dict())
        await asyncio.sleep(0.05)
    await emit("stats", tracer.stats())
    return {"generated": len(out), "events": out}


# ───────────────────────────────────────────────────────────────────────────
# WebSocket — live SOC feed
# ───────────────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_feed(ws: WebSocket):
    await hub.connect(ws)
    try:
        # Send an initial snapshot on connect.
        await ws.send_text(json.dumps({"kind": "stats", "payload": tracer.stats()}))
        await ws.send_text(json.dumps({
            "kind": "integrity", "payload": chain.verify_chain().to_dict()
        }))
        while True:
            # Keep the socket alive; ignore inbound messages.
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)
    except Exception:
        hub.disconnect(ws)


@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok", "chain_height": chain.height()})
