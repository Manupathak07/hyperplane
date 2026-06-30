"""Threat Intel agent — `lookup(ip)` is the entry point used by the
LangGraph `threat_intel_node`.

Flow:
  1. If IP is None/empty → return a zero-score envelope (no signal).
  2. If neither OTX nor AbuseIPDB keys are set → deterministic heuristic.
  3. Otherwise check the in-process cache; on miss, hit both providers in
     parallel, merge via max(), cache the envelope, return it.

The `envelope` shape is what gets stored on Incident.threat_intel AND what
the LangGraph node puts into AgentState:
  {
    "ip":         str,
    "score":      int (0-100),
    "sources":    {otx: {...}|None, abuseipdb: {...}|None, heuristic: {...}|None},
    "hits":       [{"source": str, "label": str}],
    "checked_at": iso8601 str,
  }

`hits` is a flat list of human-readable reasons the score is what it is —
useful for the Trace Viewer "Why?" panel.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.threatintel.cache import get_cached, set_cached
from app.threatintel.providers import abuseipdb_score, otx_score

log = logging.getLogger(__name__)


def normalize_ip(ip: str | None) -> str | None:
    """Return a canonical IP string or None if it's empty / not parseable."""
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()
    if not ip:
        return None
    try:
        # Validates + normalises (strips zone id, etc.). Drops IPv6 for now
        # — Week 6 scope is IPv4.
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(addr)


def _heuristic_score(ip: str) -> tuple[int, str]:
    """Return (score, label) for the deterministic-IP fallback path.

    Mirrors the ranges `threatintel_rules.py` already uses, so the smoke
    test's expectations line up exactly.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 0, "unparseable"

    # RFC5737 reserved-for-documentation ranges — known bad in demos.
    if addr in ipaddress.ip_network("198.51.100.0/24"):
        return 90, "RFC5737 TEST-NET-2"
    if addr in ipaddress.ip_network("203.0.113.0/24"):
        return 90, "RFC5737 TEST-NET-3"

    # Private ranges — local traffic, no TI signal.
    if (
        addr in ipaddress.ip_network("10.0.0.0/8")
        or addr in ipaddress.ip_network("172.16.0.0/12")
        or addr in ipaddress.ip_network("192.168.0.0/16")
        or addr.is_loopback
    ):
        return 0, "private/local"

    # Public, not in our deny-list → mildly suspicious.
    return 30, "public unknown"


async def _lookup_providers(ip: str) -> dict[str, Any]:
    """Hit OTX + AbuseIPDB in parallel. Always returns a sources dict."""
    otx_task = asyncio.create_task(otx_score(ip))
    abuse_task = asyncio.create_task(abuseipdb_score(ip))
    otx_res, abuse_res = await asyncio.gather(otx_task, abuse_task)
    return {"otx": otx_res, "abuseipdb": abuse_res}


async def lookup(ip: str | None) -> dict[str, Any]:
    """Look up `ip` and return the threat-intel envelope.

    Safe to call with None / empty / unparseable input — returns a
    zero-score envelope.
    """
    checked_at = datetime.now(timezone.utc).isoformat()
    canonical = normalize_ip(ip)
    if canonical is None:
        return {
            "ip": None,
            "score": 0,
            "sources": {"otx": None, "abuseipdb": None, "heuristic": None},
            "hits": [],
            "checked_at": checked_at,
        }

    # Cache hit short-circuits everything below.
    cached = await get_cached(canonical)
    if cached is not None:
        return cached

    sources: dict[str, Any] = {"otx": None, "abuseipdb": None, "heuristic": None}
    hits: list[dict[str, str]] = []
    score = 0

    if not settings.otx_api_key and not settings.abuseipdb_api_key:
        # Deterministic fallback — no network, no flakes.
        h_score, h_label = _heuristic_score(canonical)
        sources["heuristic"] = {"score": h_score, "label": h_label}
        hits.append({"source": "heuristic", "label": h_label})
        score = h_score
    else:
        # Real lookups — both providers in parallel.
        provider_results = await _lookup_providers(canonical)
        sources["otx"] = provider_results["otx"]
        sources["abuseipdb"] = provider_results["abuseipdb"]

        for provider_name, result in provider_results.items():
            if result is None:
                continue
            s = int(result.get("score", 0) or 0)
            score = max(score, s)
            label_bits = [f"{provider_name}={s}/100"]
            if provider_name == "otx" and result.get("pulse_count"):
                label_bits.append(f"{result['pulse_count']} pulses")
            if provider_name == "abuseipdb" and result.get("total_reports"):
                label_bits.append(f"{result['total_reports']} reports")
            hits.append({"source": provider_name, "label": ", ".join(label_bits)})

    envelope = {
        "ip": canonical,
        "score": score,
        "sources": sources,
        "hits": hits,
        "checked_at": checked_at,
    }
    await set_cached(canonical, envelope)
    return envelope


__all__ = ["lookup", "normalize_ip"]