"""ticket fields on incidents (ServiceNow integration)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-24 10:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('incidents') as batch:
        batch.add_column(sa.Column('ticket_provider', sa.String(length=32), nullable=True))
        batch.add_column(sa.Column('ticket_number', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column('ticket_url', sa.Text(), nullable=True))
        batch.add_column(sa.Column('ticket_state', sa.String(length=64), nullable=True))
        batch.add_column(
            sa.Column('ticket_synced_at', sa.DateTime(timezone=True), nullable=True)
        )
    op.create_index('ix_incidents_external_ref', 'incidents', ['external_ref'])


def downgrade() -> None:
    op.drop_index('ix_incidents_external_ref', table_name='incidents')
    with op.batch_alter_table('incidents') as batch:
        for col in ('ticket_synced_at', 'ticket_state', 'ticket_url', 'ticket_number',
                    'ticket_provider'):
            batch.drop_column(col)
