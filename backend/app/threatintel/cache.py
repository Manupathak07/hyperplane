"""In-process TTL cache for threat-intel lookups.

Week 6 — no persistence across container restarts. Re-queries after a restart
are fine; we just want to avoid hammering OTX / AbuseIPDB's free tier when
the same attacker IP shows up on 50 incidents in one minute.

Thread safety: a single asyncio.Lock guards the dict, so concurrent
investigations don't double-lookup. Per-key coalescing happens at the agent
layer (lock held around lookup-and-set).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from app.config import settings

_lock = asyncio.Lock()
_store: dict[str, tuple[float, dict]] = {}


def _now() -> float:
    return time.monotonic()


def _ttl() -> float:
    """TTL in seconds. Read from settings on every call so env changes apply."""
    return float(settings.threatintel_cache_ttl_s or 3600)


async def get_cached(ip: str) -> dict | None:
    """Return the cached payload for `ip` if it exists and is fresh, else None."""
    async with _lock:
        entry = _store.get(ip)
        if entry is None:
            return None
        expires_at, payload = entry
        if expires_at < _now():
            _store.pop(ip, None)
            return None
        return payload


async def set_cached(ip: str, payload: dict) -> None:
    """Store `payload` under `ip` with the configured TTL."""
    async with _lock:
        _store[ip] = (_now() + _ttl(), payload)


async def clear() -> None:
    """Drop everything (used by smoke tests for reproducibility)."""
    async with _lock:
        _store.clear()


def size() -> int:
    """For diagnostics — how many IPs are currently cached."""
    return len(_store)


__all__ = ["get_cached", "set_cached", "clear", "size"]