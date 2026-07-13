"""POST /events/ — accepts one or many NormalisedEvent payloads.

Behaviour (locked Week 4):
- Single event OR list of events accepted (batch).
- Each event upserted by event_id (idempotent).
- Auth: X-API-Key header required if EVENTS_API_KEY env var is set.
- Returns per-event result: {event_id, status: "created"|"duplicate", id}.
- Returns 401 if auth fails, 422 for Pydantic validation failures.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Union

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.ingestion.auth import require_api_key
from app.ingestion.normalizer import NormalisedEvent, severity_to_enum
from app.models import Incident, IncidentStatus, Severity
from app.rules import EvalContext, evaluate, recompute_severity, severity_enum_for
from app.search.indexer import index_incident
from app.websocket import manager

router = APIRouter(prefix="/events", tags=["ingest"])


class EventResult(BaseModel):
    event_id: uuid.UUID
    status: Literal["created", "duplicate"]
    id: uuid.UUID | None = None  # the Incident row id


class BatchResponse(BaseModel):
    accepted: int
    duplicates: int
    results: list[EventResult]


def _build_incident(event: NormalisedEvent) -> Incident:
    """Map a NormalisedEvent into an Incident row.

    Runs the rule engine first — if a rule demands a higher severity floor
    (e.g. OT critical asset, modbus write, numeric ≥ 9), we bump severity
    before persisting. All hits are stored as JSONB on the incident so the
    dashboard + future LangGraph agents can see what the rules decided.
    """
    sev_label = severity_to_enum(event.severity)
    initial_severity = {
        "info": Severity.LOW,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }[sev_label]

    title = f"{event.event_type} from {event.src or event.asset_id or event.host or 'unknown'}"

    raw_event = {
        "raw": event.raw,
        "parser": event.parser,
        "vendor": event.vendor,
        "tags": event.tags,
        "labels": event.labels,
        "src": event.src,
        "dst": event.dst,
        "user": event.user,
        "host": event.host,
        "asset_id": event.asset_id,
        "severity_numeric": event.severity,
        "confidence": event.confidence,
        "observed_at": event.observed_at.isoformat(),
        "correlation_id": str(event.correlation_id) if event.correlation_id else None,
    }

    # Build a minimal context for the rule engine and run it. The engine
    # only needs the structured fields; it doesn't need the ORM row.
    rule_ctx = EvalContext(
        incident_id="(pending)",  # not assigned yet — rules don't use it
        title=title,
        description=(event.tags and ", ".join(event.tags)) or None,
        event_type=event.event_type,
        domain={"it": "IT", "ot": "OT", "iot": "IoT"}[event.domain],
        severity=sev_label,
        severity_numeric=event.severity,
        source=event.parser,
        src=event.src,
        asset_id=event.asset_id,
        user=event.user,
        host=event.host,
        raw=event.raw,
        tags=list(event.tags or []),
        correlation_id=str(event.correlation_id) if event.correlation_id else None,
    )
    hits = evaluate(rule_ctx)
    adjusted_label = recompute_severity(sev_label, hits)
    final_severity = severity_enum_for(adjusted_label)

    return Incident(
        id=uuid.uuid4(),
        event_id=event.event_id,
        correlation_id=event.correlation_id,
        event_type=event.event_type,
        title=title,
        description=(event.tags and ", ".join(event.tags)) or None,
        source=event.parser,
        domain={"it": "IT", "ot": "OT", "iot": "IoT"}[event.domain],
        severity=final_severity,
        status=IncidentStatus.NEW,
        raw_event=raw_event,
        rule_hits=hits,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


async def _insert_one(session: AsyncSession, event: NormalisedEvent) -> EventResult:
    incident = _build_incident(event)
    stmt = (
        pg_insert(Incident)
        .values(**_incident_columns(incident))
        .on_conflict_do_nothing(index_elements=["event_id"])
        .returning(Incident.id)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    await session.commit()

    if row is None:
        # Duplicate — fetch the existing incident id and re-index it (idempotent
        # upsert, harmless if it was already there).
        existing = await session.execute(
            select(Incident).where(Incident.event_id == event.event_id)
        )
        existing_row = existing.scalar_one_or_none()
        if existing_row is not None:
            await index_incident(existing_row)
        return EventResult(
            event_id=event.event_id, status="duplicate",
            id=existing_row.id if existing_row else None,
        )

    # Newly inserted — the incident ORM object isn't attached to the session
    # (we used a low-level pg_insert), so re-fetch via event_id to get a
    # persistent instance for ES indexing.
    fresh = await session.execute(
        select(Incident).where(Incident.event_id == event.event_id)
    )
    fresh_row = fresh.scalar_one_or_none()
    if fresh_row is not None:
        await index_incident(fresh_row)
        # Broadcast new event to WebSocket clients
        await manager.broadcast_event(fresh_row)
    return EventResult(event_id=event.event_id, status="created", id=row)


def _incident_columns(inc: Incident) -> dict:
    """Serialise ORM object into dict for bulk-insert (avoids lazy-load issues)."""
    return {
        "id": inc.id,
        "event_id": inc.event_id,
        "correlation_id": inc.correlation_id,
        "event_type": inc.event_type,
        "title": inc.title,
        "description": inc.description,
        "source": inc.source,
        "domain": inc.domain,
        "severity": inc.severity,
        "status": inc.status,
        "raw_event": inc.raw_event,
        "rule_hits": inc.rule_hits,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
    }


@router.post(
    "/",
    response_model=BatchResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
async def ingest(
    payload: Union[NormalisedEvent, list[NormalisedEvent]],
    session: AsyncSession = Depends(get_session),
) -> BatchResponse:
    events = payload if isinstance(payload, list) else [payload]
    results: list[EventResult] = []
    accepted = 0
    duplicates = 0
    for ev in events:
        # Stamp server-side ingestion time if not set
        if ev.ingested_at is None:
            ev.ingested_at = datetime.now(timezone.utc)
        r = await _insert_one(session, ev)
        results.append(r)
        if r.status == "created":
            accepted += 1
        else:
            duplicates += 1
    return BatchResponse(accepted=accepted, duplicates=duplicates, results=results)
