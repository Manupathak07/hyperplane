"""add response field to incidents

Revision ID: 0006_response_field
Revises: 0005_detection_fields
Create Date: 2026-07-02

Week 10 — Response agent adds response column to Incident table.

Column is nullable JSONB to store response report, actions, summary, and details.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "0006_response_field"
down_revision = "0005_detection_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # response: JSONB, nullable (stores report, recommended_actions, response_summary, details)
    op.add_column('incidents', sa.Column('response', JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column('incidents', 'response')