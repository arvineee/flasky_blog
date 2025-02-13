"""update

Revision ID: 6c7a48a97d49
Revises: 
Create Date: 2024-11-15 20:22:31.502318

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6c7a48a97d49'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=150), nullable=False),
    sa.Column('password_hash', sa.String(length=256), nullable=True),
    sa.Column('is_admin', sa.Boolean(), nullable=True),
    sa.Column('date_r', sa.String(), nullable=True),
    sa.Column('is_banned', sa.Boolean(), nullable=True),
    sa.Column('warning_message', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_username'), ['username'], unique=True)

    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('desc', sa.Text(), nullable=False),
    sa.Column('date_pub', sa.String(), nullable=True),
    sa.Column('image_url', sa.String(), nullable=True),
    sa.Column('author_id', sa.Integer(), nullable=True),
    sa.Column('is_blocked', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['author_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_post_id'), ['id'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_post_id'))

    op.drop_table('post')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_username'))
        batch_op.drop_index(batch_op.f('ix_user_email'))

    op.drop_table('user')
    # ### end Alembic commands ###
