"""NormalisedEvent — the common envelope every parser must produce.

This is the contract between ingestion (Week 4) and the agent pipeline
(Weeks 6+). The agent pipeline only ever sees NormalisedEvent-shaped data
plus the Incident ORM row. Parsers never talk to agents directly.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Domain = Literal["it", "ot", "iot"]


class NormalisedEvent(BaseModel):
    """The single shape every parser must produce.

    Required fields (parsers MUST set):
      - domain, event_type, observed_at, raw, parser

    Optional fields populated as available:
      - src/dst/user/host/asset_id, severity (0-10), confidence (0-1),
        vendor, tags, labels, correlation_id

    Identity:
      - event_id: UUID4. Client can supply; server generates if missing.
        Used for idempotency (duplicate detection).
      - ingested_at: server-stamped on insert.
    """

    # --- Identity ----------------------------------------------------------
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ingested_at: datetime | None = None  # server fills

    # --- When + what --------------------------------------------------------
    observed_at: datetime
    domain: Domain
    event_type: str  # dotted: "auth.login_failed", "modbus.register_write"
    severity: int = Field(default=0, ge=0, le=10)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    # --- Entities (all optional, source-dependent) -------------------------
    src: str | None = None
    dst: str | None = None
    user: str | None = None
    host: str | None = None
    asset_id: str | None = None

    # --- Provenance + context ---------------------------------------------
    raw: str
    parser: str  # which parser produced this: "syslog", "evtx", "modbus", "mqtt", "opcua"
    vendor: str | None = None  # e.g. "linux", "schneider", "honeywell"
    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)

    # --- Correlation (Week 6+ enrichment can write here) -----------------
    correlation_id: uuid.UUID | None = None


def parse_failed_event(raw: str, parser: str, reason: str) -> NormalisedEvent:
    """Helper for parsers: produce a NormalisedEvent that says "I couldn't
    parse this but I'm storing it anyway". Confidence is 0 so downstream
    agents know not to trust it.
    """
    return NormalisedEvent(
        observed_at=datetime.now(timezone.utc),
        domain="it",  # best-effort default; refined later if recognisable
        event_type="parse_failed",
        severity=0,
        confidence=0.0,
        raw=raw,
        parser=parser,
        tags=[f"reason:{reason}"],
        labels={"parse_error": reason},
    )


def severity_to_enum(severity: int) -> str:
    """Map numeric severity (0-10) to display enum used in the dashboard."""
    if severity >= 9:
        return "critical"
    if severity >= 7:
        return "high"
    if severity >= 5:
        return "medium"
    if severity >= 3:
        return "low"
    return "info"
