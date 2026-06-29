"""Search endpoint — full-text + filter over the Elasticsearch index.

Backed by `app.search.query.search_incidents`. Postgres remains the source of
truth; this is just the query side of the indexer pipeline (Week 5 Chunk 1).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from app.search.query import search_incidents

router = APIRouter(prefix="/search", tags=["search"])


@router.get("/")
async def search(
    q: Optional[str] = Query(default=None, description="Free-text query (title/description/raw)"),
    domain: Optional[str] = Query(default=None, description="Filter by domain (IT|OT)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (low|medium|high|critical)"),
    status: Optional[str] = Query(default=None, description="Filter by status (new|triaging|...)"),
    correlation_id: Optional[str] = Query(default=None, description="Filter by correlation_id"),
    size: int = Query(default=50, ge=1, le=500),
    from_: int = Query(default=0, ge=0, alias="from"),
) -> dict:
    """Search incidents.

    Returns `{"total": N, "hits": [...]}` where each hit is the ES `_source`
    document — same fields the IncidentRead model exposes (id, title, severity,
    etc.) plus event_id + correlation_id at the top level.
    """
    return await search_incidents(
        q=q,
        domain=domain,
        severity=severity,
        status=status,
        correlation_id=correlation_id,
        size=size,
        from_=from_,
    )