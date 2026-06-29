"""Query-side helpers for the incidents search endpoint.

`search_incidents` builds an Elasticsearch query from the user-facing filters
(simple_query_string over title+description, plus exact-match filters for
domain/severity/status) and returns ES hits projected back to a dict shape the
Pydantic response model understands.
"""
from __future__ import annotations

from typing import Any, Optional

from . import INDEX_NAME, get_es


async def search_incidents(
    *,
    q: Optional[str] = None,
    domain: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    correlation_id: Optional[str] = None,
    size: int = 50,
    from_: int = 0,
) -> dict[str, Any]:
    """Run a search against the incidents index.

    Returns `{"hits": [...], "total": N}` — mirrors the /incidents/ list shape
    so the frontend can reuse the row component.
    """
    must: list[dict] = []
    filters: list[dict] = []

    if q:
        # simple_query_string is forgiving: handles typos, missing operators,
        # quoted phrases. Search title (boosted) + description + raw.
        must.append({
            "simple_query_string": {
                "query": q,
                "fields": ["title^3", "description", "raw"],
                "default_operator": "and",
            }
        })
    if domain:
        filters.append({"term": {"domain": domain}})
    if severity:
        filters.append({"term": {"severity": severity}})
    if status:
        filters.append({"term": {"status": status}})
    if correlation_id:
        filters.append({"term": {"correlation_id": correlation_id}})

    if must or filters:
        query: dict = {"bool": {}}
        if must:
            query["bool"]["must"] = must
        if filters:
            query["bool"]["filter"] = filters
    else:
        query = {"match_all": {}}

    es = get_es()
    resp = await es.search(
        index=INDEX_NAME,
        query=query,
        size=size,
        from_=from_,
        sort=[{"created_at": {"order": "desc"}}],
    )

    hits = resp.get("hits", {})
    total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
    return {
        "total": total,
        "hits": [h["_source"] for h in hits.get("hits", [])],
    }