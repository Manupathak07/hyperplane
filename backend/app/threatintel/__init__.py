"""Threat Intel agent — IP-based reputation lookups + score.

Week 6. Sub-package layout:

    providers.py   — OTX + AbuseIPDB async clients (httpx)
    cache.py       — in-process TTL cache (one entry per IP)
    agent.py       — `lookup(ip)` orchestrator + heuristic fallback

When OTX_API_KEY / ABUSEIPDB_API_KEY env vars are empty (dev / demo default),
the agent falls back to a deterministic IP-based heuristic so the smoke test
stays reproducible and the demo never hits the network.

Heuristic scores (RFC5737 reserved ranges are clearly bad, private is local):
  198.51.100.0/24 (TEST-NET-2)  → 90
  203.0.113.0/24  (TEST-NET-3)  → 90
  10.0.0.0/8, 172.16/12, 192.168/16 (private) → 0
  anything else (public, unknown) → 30
  no IP                          → 0
"""
from __future__ import annotations

from app.threatintel.agent import lookup, normalize_ip
from app.threatintel.cache import get_cached, set_cached

__all__ = ["lookup", "normalize_ip", "get_cached", "set_cached"]