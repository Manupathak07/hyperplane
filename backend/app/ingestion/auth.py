"""API key auth for the events ingest endpoint.

Behaviour:
- If EVENTS_API_KEY env var is unset → auth disabled (dev convenience).
- If set → X-API-Key header MUST match. Mismatch → 401.
- Generator uses an internal key set in docker-compose.yml.

Future (out of scope Week 4): rotate keys, per-source keys, JWT.
"""
from fastapi import Header, HTTPException, status

from app.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency: validates X-API-Key header if auth is enabled."""
    expected = settings.events_api_key
    if not expected:
        # Auth disabled — local dev
        return
    if x_api_key is None or x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
