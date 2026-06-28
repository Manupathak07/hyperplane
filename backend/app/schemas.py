"""Pydantic schemas for API I/O. Decoupled from ORM models so the wire format
can evolve independently of the database."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import (
    AgentName,
    Domain,
    IncidentStatus,
    Severity,
    TraceStatus,
)


# --- Incident -------------------------------------------------------------


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    source: str
    domain: Domain
    severity: Severity = Severity.MEDIUM
    raw_event: dict


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str | None
    source: str
    domain: Domain
    severity: Severity
    status: IncidentStatus
    raw_event: dict
    created_at: datetime
    updated_at: datetime


# --- Agent trace ----------------------------------------------------------


class AgentTraceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_name: AgentName
    step: int
    input: dict
    output: dict
    reasoning: str | None
    duration_ms: int | None
    status: TraceStatus
    created_at: datetime


# --- Normalized incident --------------------------------------------------


class NormalizedIncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_ip: str | None
    destination_ip: str | None
    geo: dict | None
    asset_id: str | None
    user_id: str | None
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    threat_score: int
    indicators: dict
    created_at: datetime


# --- Aggregate view (for the Trace Viewer UI) -----------------------------


class IncidentDetail(IncidentRead):
    """An incident with all its traces and normalized view eagerly loaded."""

    traces: list[AgentTraceRead] = []
    normalized: NormalizedIncidentRead | None = None
