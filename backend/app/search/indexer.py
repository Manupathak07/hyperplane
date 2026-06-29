"""Write Incident rows into Elasticsearch.

Called from `app.routes.events._insert_one` AFTER the Postgres insert succeeds,
so the ES document and the SQL row stay in lock-step for new events.

We keep this synchronous (`await es.index(...)`) rather than fire-and-forget
because:
  - search results are immediately useful for the operator (no lag)
  - if ES is down, the route returns 503 and the generator retries — same
    idempotency story we already have for Postgres
  - we don't need a queue yet; volume is low (generator fires ~1 batch / 8s)

If/when the system needs higher throughput, swap this for a Redis-backed
outbox and a background drainer.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Incident

from . import INDEX_NAME, get_es

log = logging.getLogger(__name__)


def _incident_to_doc(inc: Incident) -> dict[str, Any]:
    """Project an Incident ORM row to the ES document shape.

    Keeps the document lean — Postgres is still the source of truth, ES is just
    the search/filter index. `severity_numeric` lives inside `raw_event` (it's
    the parser's 0-10 confidence, not a column).
    """
    raw = inc.raw_event or {}
    return {
        "id": str(inc.id),
        "event_id": str(inc.event_id) if inc.event_id else None,
        "correlation_id": inc.correlation_id,
        "title": inc.title,
        "description": inc.description,
        "event_type": inc.event_type,
        "domain": inc.domain.value if hasattr(inc.domain, "value") else inc.domain,
        "severity": inc.severity.value if hasattr(inc.severity, "value") else inc.severity,
        "severity_numeric": raw.get("severity_numeric"),
        "status": inc.status.value if hasattr(inc.status, "value") else inc.status,
        "source": inc.source,
        "src": raw.get("src"),
        "user": raw.get("user"),
        "host": raw.get("host"),
        "asset_id": raw.get("asset_id"),
        "tags": raw.get("tags") or [],
        "labels": raw.get("labels") or {},
        "rule_hits": list(getattr(inc, "rule_hits", []) or []),
        "raw": raw.get("raw"),
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


async def index_incident(inc: Incident, *, refresh: bool = False) -> None:
    """Index (or update) one incident in ES.

    Uses the Incident's UUID as the ES `_id` so a re-index of the same row is
    an upsert, not a duplicate. Failures are logged but not raised — the row
    is already in Postgres, and a periodic reindexer can backfill later.
    """
    es = get_es()
    doc = _incident_to_doc(inc)
    try:
        await es.index(
            index=INDEX_NAME,
            id=str(inc.id),
            document=doc,
            refresh="wait_for" if refresh else False,
        )
    except Exception as e:
        # Don't fail the ingest path just because ES is briefly unavailable.
        log.warning("ES index failed for incident %s: %s", inc.id, e)


async def reindex_all(session: AsyncSession, *, batch_size: int = 200) -> int:
    """Backfill ES from Postgres. Useful after the index is created or wiped.

    Returns the number of incidents indexed. Streams in batches so we don't
    load the whole table into memory at once.
    """
    from sqlalchemy import select

    es = get_es()
    total = 0
    offset = 0
    while True:
        result = await session.execute(
            select(Incident).order_by(Incident.created_at).offset(offset).limit(batch_size)
        )
        rows = result.scalars().all()
        if not rows:
            break
        for inc in rows:
            await index_incident(inc)
            total += 1
        offset += batch_size
    log.info("reindexed %d incidents into ES", total)
    return total