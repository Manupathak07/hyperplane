"""add rule_hits JSONB column to incidents

Revision ID: 0003_rule_hits
Revises: 0002_ingestion_columns
Create Date: 2026-06-29

Persists the output of the lightweight rule engine (Week 5 Chunk 2) on each
incident. Default `[]` so existing rows stay valid without a per-row update.

Schema (per element):
  {
    "rule_id":    str,        # stable id, e.g. "severity_floor_ot"
    "rule_name":  str,        # human-readable
    "severity":   str,        # info|low|medium|high|critical
    "confidence": float,      # 0.0-1.0
    "matched":    {...},      # arbitrary evidence
    "description": str        # one-line explanation
  }
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "0003_rule_hits"
down_revision = "0002_ingestion_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("rule_hits", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("incidents", "rule_hits")