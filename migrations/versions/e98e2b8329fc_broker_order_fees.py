"""broker order fees

Revision ID: e98e2b8329fc
Revises: 9131b7c1162b
Create Date: 2022-10-26 03:16:53.134344

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e98e2b8329fc'
down_revision = '9131b7c1162b'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('broker_order', sa.Column('quote_fee', sa.BigInteger(), nullable=True))
    op.add_column('broker_order', sa.Column('quote_fee_fixed', sa.BigInteger(), nullable=True))


def downgrade():
    op.drop_column('broker_order', 'quote_fee_fixed')
    op.drop_column('broker_order', 'quote_fee')
