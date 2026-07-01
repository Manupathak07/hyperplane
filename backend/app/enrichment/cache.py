"""Enrichment cache layer.

Simple in-memory TTL cache for enrichment data like GeoIP lookups.
For production, this could be backed by Redis or similar.
"""
from __future__ import annotations

import time
from typing import Any, Optional, Tuple


class TTLCache:
    """Simple thread-unsafe TTL cache."""
    
    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, Any]] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache if not expired."""
        if key in self._cache:
            expiry, value = self._cache[key]
            if time.time() < expiry:
                return value
            else:
                # Expired, remove it
                del self._cache[key]
        return None
    
    def set(self, key: str, value: Any) -> None:
        """Set item in cache with TTL."""
        expiry = time.time() + self._ttl
        self._cache[key] = (expiry, value)
    
    def delete(self, key: str) -> None:
        """Delete item from cache."""
        self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()


# Global cache instances
_geo_cache = TTLCache(ttl_seconds=300)  # 5 minute TTL for GeoIP
_asset_cache = TTLCache(ttl_seconds=600)  # 10 minute TTL for asset lookups


async def get_cached_geo(ip: str) -> Optional[dict]:
    """Get cached GeoIP lookup result."""
    return _geo_cache.get(ip)


async def set_cached_geo(ip: str, data: dict) -> None:
    """Cache GeoIP lookup result."""
    _geo_cache.set(ip, data)


async def get_cached_asset(ip: str) -> Optional[str]:
    """Cached asset lookup result."""
    return _asset_cache.get(ip)


async def set_cached_asset(ip: str, asset_id: str) -> None:
    """Cache asset lookup result."""
    _asset_cache.set(ip, asset_id)


__all__ = [
    "get_cached_geo", "set_cached_geo",
    "get_cached_asset", "set_cached_asset"
]
