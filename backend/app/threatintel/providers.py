"""Threat-intel providers: OTX (AlienVault) + AbuseIPDB.

Both expose a single async function `score_ip(ip) -> dict | None` that returns
the raw provider payload + a normalised 0-100 score, or None on any error.

We deliberately swallow every exception here — a provider outage must never
take down the investigation pipeline. Errors are logged at WARNING with the
provider name + IP so they show up in the backend logs.

Score mapping:
  - OTX:        pulse_count bucketed — 1=20, 2=40, 3=60, 5+=80, 10+=100.
                Bonus +10 if any pulse tagged "malware".
  - AbuseIPDB:  abuseConfidenceScore field directly (already 0-100).

Caller (`agent.lookup`) merges the two via max() and stores both raw payloads
in `sources` so the Trace Viewer can show what each provider said.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
_UA = "HyperPlane/0.1 (agentic-siem; +https://github.com/manup/hyperplane)"

# ---------------------------------------------------------------------------
# OTX (AlienVault Open Threat Exchange) — no key needed for the basic
# /general endpoint, but OTX recommends registering for higher rate limits.
# ---------------------------------------------------------------------------
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


async def otx_score(ip: str) -> dict[str, Any] | None:
    """Hit OTX for `ip`, return {score, pulse_count, malware_pulses, raw}."""
    url = OTX_URL.format(ip=ip)
    headers = {"User-Agent": _UA}
    if settings.otx_api_key:
        headers["X-OTX-API-KEY"] = settings.otx_api_key
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        log.warning("OTX lookup failed for %s: %s", ip, e)
        return None

    pulse_count = int(data.get("pulse_info", {}).get("count", 0) or 0)
    pulses = data.get("pulse_info", {}).get("pulses", []) or []
    malware_pulses = sum(
        1 for p in pulses
        if any("malware" in (t or "").lower() for t in (p.get("tags") or []))
    )

    if pulse_count >= 10:
        base = 100
    elif pulse_count >= 5:
        base = 80
    elif pulse_count >= 3:
        base = 60
    elif pulse_count >= 2:
        base = 40
    elif pulse_count >= 1:
        base = 20
    else:
        base = 0

    score = min(100, base + (10 if malware_pulses else 0))

    return {
        "score": score,
        "pulse_count": pulse_count,
        "malware_pulses": malware_pulses,
        "raw": data,
    }


# ---------------------------------------------------------------------------
# AbuseIPDB — REQUIRES an API key. Without one we return None immediately.
# ---------------------------------------------------------------------------
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def abuseipdb_score(ip: str) -> dict[str, Any] | None:
    """Hit AbuseIPDB for `ip`, return {score, total_reports, country, raw}."""
    if not settings.abuseipdb_api_key:
        return None
    url = ABUSEIPDB_URL
    headers = {
        "User-Agent": _UA,
        "Accept": "application/json",
        "Key": settings.abuseipdb_api_key,
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url, headers=headers, params=params)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        log.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
        return None

    payload = data.get("data") or {}
    score = int(payload.get("abuseConfidenceScore", 0) or 0)
    return {
        "score": max(0, min(100, score)),
        "total_reports": int(payload.get("totalReports", 0) or 0),
        "country": payload.get("countryCode"),
        "raw": data,
    }


__all__ = ["otx_score", "abuseipdb_score"]