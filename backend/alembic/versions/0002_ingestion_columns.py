"""add event_id + correlation_id + event_type to incidents

Revision ID: 0002_ingestion_columns
Revises: 0001
Create Date: 2026-06-28

Backfills any pre-existing rows with random UUIDs before enforcing NOT NULL,
so this migration is safe on a DB that already has incidents (e.g. from earlier
seeds).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
import uuid as _uuid


# revision identifiers, used by Alembic.
revision = "0002_ingestion_columns"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Add columns nullable so the ALTER doesn't fail on existing rows.
    op.add_column(
        "incidents",
        sa.Column("event_id", UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("correlation_id", UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("event_type", sa.String(128), nullable=True),
    )

    # 2) Backfill event_id + event_type on any pre-existing rows.
    op.execute(
        "UPDATE incidents SET event_id = gen_random_uuid() WHERE event_id IS NULL"
    )
    op.execute(
        "UPDATE incidents SET event_type = 'unknown' WHERE event_type IS NULL"
    )

    # 3) Enforce NOT NULL now that data is backfilled.
    op.alter_column("incidents", "event_id", nullable=False)
    op.alter_column("incidents", "event_type", nullable=False)

    # 4) Unique index on event_id (drives idempotency in /events/) + lookup index
    op.create_index(
        "ix_incidents_event_id", "incidents", ["event_id"], unique=True
    )
    op.create_index(
        "ix_incidents_correlation_id", "incidents", ["correlation_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_incidents_correlation_id", table_name="incidents")
    op.drop_index("ix_incidents_event_id", table_name="incidents")
    op.drop_column("incidents", "event_type")
    op.drop_column("incidents", "correlation_id")
    op.drop_column("incidents", "event_id")