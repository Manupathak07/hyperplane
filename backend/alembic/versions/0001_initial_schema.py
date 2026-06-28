"""initial schema — incidents, agent_traces, normalized_incidents

Revision ID: 0001
Revises:
Create Date: 2026-06-27
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # Postgres enum types — created explicitly so the SAEnum columns can reference them.
    domain_enum = postgresql.ENUM(
        "IT", "OT", "IoT", name="domain_enum", create_type=False
    )
    severity_enum = postgresql.ENUM(
        "low", "medium", "high", "critical",
        name="severity_enum", create_type=False,
    )
    incident_status_enum = postgresql.ENUM(
        "new", "triaging", "investigating", "contained", "closed",
        name="incident_status_enum", create_type=False,
    )
    agent_name_enum = postgresql.ENUM(
        "supervisor", "triage", "threat_intel", "enrichment", "detection", "response",
        name="agent_name_enum", create_type=False,
    )
    trace_status_enum = postgresql.ENUM(
        "success", "failed", "skipped", name="trace_status_enum", create_type=False
    )

    for enum in (
        domain_enum,
        severity_enum,
        incident_status_enum,
        agent_name_enum,
        trace_status_enum,
    ):
        enum.create(bind, checkfirst=True)

    # --- incidents --------------------------------------------------------
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("domain", domain_enum, nullable=False),
        sa.Column("severity", severity_enum, nullable=False, server_default="medium"),
        sa.Column("status", incident_status_enum, nullable=False, server_default="new"),
        sa.Column("raw_event", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_incidents_domain", "incidents", ["domain"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])

    # --- agent_traces -----------------------------------------------------
    op.create_table(
        "agent_traces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_name", agent_name_enum, nullable=False),
        sa.Column("step", sa.Integer, nullable=False),
        sa.Column("input", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("output", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("reasoning", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("status", trace_status_enum, nullable=False, server_default="success"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_agent_traces_incident_id", "agent_traces", ["incident_id"])
    op.create_index("ix_agent_traces_agent_name", "agent_traces", ["agent_name"])

    # --- normalized_incidents ---------------------------------------------
    op.create_table(
        "normalized_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("geo", postgresql.JSONB, nullable=True),
        sa.Column("asset_id", sa.String(128), nullable=True),
        sa.Column("user_id", sa.String(128), nullable=True),
        sa.Column("mitre_tactics", postgresql.ARRAY(sa.String), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("threat_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("indicators", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_table("normalized_incidents")
    op.drop_table("agent_traces")
    op.drop_table("incidents")

    for name in (
        "trace_status_enum",
        "agent_name_enum",
        "incident_status_enum",
        "severity_enum",
        "domain_enum",
    ):
        sa.Enum(name=name).drop(bind, checkfirst=True)
