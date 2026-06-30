"""add threat_intel JSONB column to incidents

Revision ID: 0004_threat_intel
Revises: 0003_rule_hits
Create Date: 2026-06-30

Week 6 — Threat Intel agent output persisted alongside the incident so the
dashboard / Trace Viewer can show "we checked this IP and it scored 92/100".
Default `{}` so existing rows stay valid without a per-row update.

Schema (per element):
  {
    "score":       int,             # 0-100, max(otx, abuseipdb, heuristic)
    "sources":     {otx: {...}|None, abuseipdb: {...}|None},
    "hits":        [{"source": str, "label": str}],
    "checked_at":  iso8601 str,
  }
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "0004_threat_intel"
down_revision = "0003_rule_hits"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("threat_intel", JSONB, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("incidents", "threat_intel")