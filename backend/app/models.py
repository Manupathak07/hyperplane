"""SQLAlchemy ORM models for HyperPlane.

Three tables back the 6-agent pipeline:

    incidents           — one row per detected event (the core record)
    agent_traces        — one row per agent step (powers the Trace Viewer)
    normalized_incidents — one row per incident, post-enrichment view
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    ARRAY,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


# --- Enums ----------------------------------------------------------------


class Domain(str, enum.Enum):
    IT = "IT"
    OT = "OT"
    IOT = "IoT"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class AgentName(str, enum.Enum):
    SUPERVISOR = "supervisor"
    TRIAGE = "triage"
    THREAT_INTEL = "threat_intel"
    ENRICHMENT = "enrichment"
    DETECTION = "detection"
    RESPONSE = "response"


class TraceStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


# --- Models ----------------------------------------------------------------


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Idempotency key — ingest endpoint dedupes on this. Unique.
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, index=True, nullable=False
    )
    # Optional correlation chain id — multiple incidents can share one.
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    domain: Mapped[Domain] = mapped_column(
        SAEnum(Domain, name="domain_enum", values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity_enum", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=Severity.MEDIUM,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        SAEnum(IncidentStatus, name="incident_status_enum", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=IncidentStatus.NEW,
    )
    raw_event: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # Rule-engine output — list of {rule_id, rule_name, severity, confidence,
    # matched, description}. Always a list (possibly empty).
    rule_hits: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Threat-Intel agent output for this incident. Shape (Week 6):
    #   {"score": int, "sources": {otx: {...}|None, abuseipdb: {...}|None},
    #    "hits": [{"source": str, "label": str}], "checked_at": iso8601}
    # Default {} so existing rows stay valid; populated by the Threat Intel
    # node when /investigate runs.
    threat_intel: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    traces: Mapped[list["AgentTrace"]] = relationship(
        "AgentTrace",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="AgentTrace.step",
    )
    normalized: Mapped["NormalizedIncident | None"] = relationship(
        "NormalizedIncident",
        back_populates="incident",
        uselist=False,
        cascade="all, delete-orphan",
    )


class AgentTrace(Base):
    __tablename__ = "agent_traces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_name: Mapped[AgentName] = mapped_column(
        SAEnum(AgentName, name="agent_name_enum", values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    step: Mapped[int] = mapped_column(Integer, nullable=False)
    input: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    output: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[TraceStatus] = mapped_column(
        SAEnum(TraceStatus, name="trace_status_enum", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=TraceStatus.SUCCESS,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="traces")


class NormalizedIncident(Base):
    __tablename__ = "normalized_incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    geo: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_tactics: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indicators: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="normalized"
    )
