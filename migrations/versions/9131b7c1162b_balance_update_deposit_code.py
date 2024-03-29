"""balance update deposit code

Revision ID: 9131b7c1162b
Revises: 582a80fd3fda
Create Date: 2022-08-28 09:43:20.218510

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9131b7c1162b'
down_revision = '582a80fd3fda'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('balance_update', sa.Column('deposit_code_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'balance_update', 'fiat_deposit_code', ['deposit_code_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'balance_update', type_='foreignkey')
    op.drop_column('balance_update', 'deposit_code_id')
    # ### end Alembic commands ###
