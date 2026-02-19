"""Initial database schema for PKI CA Admin

Revision ID: 001
Revises: 
Create Date: 2026-02-19 07:31:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ca_nodes table
    op.create_table('ca_nodes',
        sa.Column('id', postgresql.UUID(), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('parent_ca_id', postgresql.UUID(), nullable=True),
        sa.Column('subject_dn', sa.String(length=500), nullable=False),
        sa.Column('certificate_pem', sa.Text(), nullable=True),
        sa.Column('certificate_chain_pem', sa.Text(), nullable=True),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('key_type', sa.String(length=50), nullable=False),
        sa.Column('key_storage', sa.String(length=50), nullable=False),
        sa.Column('kms_key_id', sa.String(length=512), nullable=True),
        sa.Column('kms_region', sa.String(length=50), nullable=True),
        sa.Column('max_path_length', sa.Integer(), nullable=True),
        sa.Column('allowed_key_types', postgresql.ARRAY(sa.String(length=100)), nullable=True),
        sa.Column('max_validity_days', sa.Integer(), nullable=False, default=365),
        sa.Column('crl_distribution_points', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('ocsp_responder_url', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, default='active'),
        sa.Column('auto_renewal', sa.Boolean(), nullable=False, default=False),
        sa.Column('renewal_threshold_days', sa.Integer(), nullable=False, default=30),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['parent_ca_id'], ['ca_nodes.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for ca_nodes
    op.create_index('ix_ca_nodes_type', 'ca_nodes', ['type'])
    op.create_index('ix_ca_nodes_status', 'ca_nodes', ['status'])
    op.create_index('ix_ca_nodes_parent_id', 'ca_nodes', ['parent_ca_id'])
    op.create_index('ix_ca_nodes_not_after', 'ca_nodes', ['not_after'])

    # Create certificates table
    op.create_table('certificates',
        sa.Column('id', postgresql.UUID(), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('ca_id', postgresql.UUID(), nullable=False),
        sa.Column('serial_number', sa.String(length=128), nullable=False),
        sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True),
        sa.Column('common_name', sa.String(length=255), nullable=False),
        sa.Column('subject_dn', sa.String(length=500), nullable=True),
        sa.Column('subject_alternative_names', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('certificate_pem', sa.Text(), nullable=True),
        sa.Column('certificate_der', sa.LargeBinary(), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=False),
        sa.Column('certificate_type', sa.String(length=50), nullable=False),
        sa.Column('key_type', sa.String(length=50), nullable=True),
        sa.Column('key_usage', postgresql.ARRAY(sa.String(length=100)), nullable=True),
        sa.Column('extended_key_usage', postgresql.ARRAY(sa.String(length=100)), nullable=True),
        sa.Column('provisioner_id', postgresql.UUID(), nullable=True),
        sa.Column('template_id', postgresql.UUID(), nullable=True),
        sa.Column('requester', sa.String(length=255), nullable=True),
        sa.Column('request_source', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, default='active'),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(length=100), nullable=True),
        sa.Column('revoked_by', sa.String(length=255), nullable=True),
        sa.Column('certificate_transparency_scts', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.ForeignKeyConstraint(['ca_id'], ['ca_nodes.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for certificates
    op.create_index('ix_certificates_ca_serial', 'certificates', ['ca_id', 'serial_number'], unique=True)
    op.create_index('ix_certificates_fingerprint', 'certificates', ['fingerprint_sha256'])
    op.create_index('ix_certificates_not_after', 'certificates', ['not_after'])
    op.create_index('ix_certificates_status', 'certificates', ['status'])
    op.create_index('ix_certificates_common_name', 'certificates', ['common_name'])
    op.create_index('ix_certificates_certificate_type', 'certificates', ['certificate_type'])

    # Create audit_events table
    op.create_table('audit_events',
        sa.Column('id', sa.BigInteger(), nullable=False, primary_key=True),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('event_category', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('entity_id', postgresql.UUID(), nullable=False),
        sa.Column('actor_type', sa.String(length=50), nullable=True),
        sa.Column('actor_id', sa.String(length=255), nullable=True),
        sa.Column('actor_ip', postgresql.INET(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('event_data', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('changes', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('request_id', sa.String(length=255), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()'))
    )
    
    # Create indexes for audit_events
    op.create_index('ix_audit_events_created_at', 'audit_events', ['created_at'])
    op.create_index('ix_audit_events_event_type', 'audit_events', ['event_type'])
    op.create_index('ix_audit_events_entity', 'audit_events', ['entity_type', 'entity_id'])
    op.create_index('ix_audit_events_actor', 'audit_events', ['actor_type', 'actor_id'])
    op.create_index('ix_audit_events_severity', 'audit_events', ['severity'])

    # Add constraints
    op.create_check_constraint(
        'valid_ca_type', 
        'ca_nodes',
        "type IN ('root', 'intermediate')"
    )
    
    op.create_check_constraint(
        'root_has_no_parent',
        'ca_nodes', 
        "(type = 'root' AND parent_ca_id IS NULL) OR (type = 'intermediate' AND parent_ca_id IS NOT NULL)"
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('audit_events')
    op.drop_table('certificates')
    op.drop_table('ca_nodes')