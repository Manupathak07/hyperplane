"""add detection fields to incidents

Revision ID: 0005_detection_fields
Revises: 0004_threat_intel
Create Date: 2026-07-01

Week 9 — Detection agent adds detection_score, attack_stage,
related_incident_ids, and detection_details to Incident table.

Columns are nullable where appropriate with sensible defaults.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY


# revision identifiers, used by Alembic.
revision = "0005_detection_fields"
down_revision = "0004_threat_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # detection_score: integer, not null, default 0
    op.add_column('incidents', sa.Column('detection_score', sa.Integer(), nullable=False, server_default='0'))
    # attack_stage: string up to 64, nullable
    op.add_column('incidents', sa.Column('attack_stage', sa.String(length=64), nullable=True))
    # related_incident_ids: JSONB array of UUIDs, not null, default empty array
    op.add_column('incidents', sa.Column('related_incident_ids', JSONB, nullable=False, server_default='[]'))
    # detection_details: JSONB, nullable (could default to {} but keep nullable)
    op.add_column('incidents', sa.Column('detection_details', JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column('incidents', 'detection_details')
    op.drop_column('incidents', 'related_incident_ids')
    op.drop_column('incidents', 'attack_stage')
    op.drop_column('incidents', 'detection_score')
