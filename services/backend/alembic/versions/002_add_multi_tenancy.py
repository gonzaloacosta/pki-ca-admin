"""Add multi-tenancy support

Revision ID: 002
Revises: 001
Create Date: 2026-02-19 07:35:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add tenant_id column to ca_nodes
    op.add_column('ca_nodes', sa.Column('tenant_id', sa.String(length=100), nullable=True))
    
    # Set default tenant_id for existing records
    op.execute("UPDATE ca_nodes SET tenant_id = 'default' WHERE tenant_id IS NULL")
    
    # Make tenant_id non-nullable
    op.alter_column('ca_nodes', 'tenant_id', nullable=False)
    
    # Add tenant_id column to certificates
    op.add_column('certificates', sa.Column('tenant_id', sa.String(length=100), nullable=True))
    
    # Set default tenant_id for existing records
    op.execute("UPDATE certificates SET tenant_id = 'default' WHERE tenant_id IS NULL")
    
    # Make tenant_id non-nullable
    op.alter_column('certificates', 'tenant_id', nullable=False)
    
    # Add tenant_id column to audit_events
    op.add_column('audit_events', sa.Column('tenant_id', sa.String(length=100), nullable=True))
    
    # Set default tenant_id for existing records
    op.execute("UPDATE audit_events SET tenant_id = 'default' WHERE tenant_id IS NULL")
    
    # Make tenant_id non-nullable
    op.alter_column('audit_events', 'tenant_id', nullable=False)
    
    # Drop old indexes
    op.drop_index('ix_ca_nodes_type', table_name='ca_nodes')
    op.drop_index('ix_ca_nodes_status', table_name='ca_nodes')
    
    # Create new tenant-aware indexes for ca_nodes
    op.create_index('ix_ca_nodes_tenant_id', 'ca_nodes', ['tenant_id'])
    op.create_index('ix_ca_nodes_tenant_type', 'ca_nodes', ['tenant_id', 'type'])
    op.create_index('ix_ca_nodes_tenant_status', 'ca_nodes', ['tenant_id', 'status'])
    
    # Drop old indexes for certificates
    op.drop_index('ix_certificates_status', table_name='certificates')
    op.drop_index('ix_certificates_common_name', table_name='certificates')
    op.drop_index('ix_certificates_certificate_type', table_name='certificates')
    
    # Create new tenant-aware indexes for certificates
    op.create_index('ix_certificates_tenant_id', 'certificates', ['tenant_id'])
    op.create_index('ix_certificates_tenant_status', 'certificates', ['tenant_id', 'status'])
    op.create_index('ix_certificates_tenant_common_name', 'certificates', ['tenant_id', 'common_name'])
    op.create_index('ix_certificates_tenant_type', 'certificates', ['tenant_id', 'certificate_type'])
    op.create_index('ix_certificates_tenant_not_after', 'certificates', ['tenant_id', 'not_after'])
    
    # Drop old indexes for audit_events
    op.drop_index('ix_audit_events_created_at', table_name='audit_events')
    op.drop_index('ix_audit_events_event_type', table_name='audit_events')
    op.drop_index('ix_audit_events_entity', table_name='audit_events')
    op.drop_index('ix_audit_events_actor', table_name='audit_events')
    op.drop_index('ix_audit_events_severity', table_name='audit_events')
    
    # Create new tenant-aware indexes for audit_events
    op.create_index('ix_audit_events_tenant_id', 'audit_events', ['tenant_id'])
    op.create_index('ix_audit_events_tenant_created_at', 'audit_events', ['tenant_id', 'created_at'])
    op.create_index('ix_audit_events_tenant_event_type', 'audit_events', ['tenant_id', 'event_type'])
    op.create_index('ix_audit_events_tenant_entity', 'audit_events', ['tenant_id', 'entity_type', 'entity_id'])
    op.create_index('ix_audit_events_tenant_actor', 'audit_events', ['tenant_id', 'actor_type', 'actor_id'])
    op.create_index('ix_audit_events_tenant_severity', 'audit_events', ['tenant_id', 'severity'])


def downgrade() -> None:
    # Drop tenant-aware indexes for audit_events
    op.drop_index('ix_audit_events_tenant_severity', table_name='audit_events')
    op.drop_index('ix_audit_events_tenant_actor', table_name='audit_events')
    op.drop_index('ix_audit_events_tenant_entity', table_name='audit_events')
    op.drop_index('ix_audit_events_tenant_event_type', table_name='audit_events')
    op.drop_index('ix_audit_events_tenant_created_at', table_name='audit_events')
    op.drop_index('ix_audit_events_tenant_id', table_name='audit_events')
    
    # Recreate old indexes for audit_events
    op.create_index('ix_audit_events_severity', 'audit_events', ['severity'])
    op.create_index('ix_audit_events_actor', 'audit_events', ['actor_type', 'actor_id'])
    op.create_index('ix_audit_events_entity', 'audit_events', ['entity_type', 'entity_id'])
    op.create_index('ix_audit_events_event_type', 'audit_events', ['event_type'])
    op.create_index('ix_audit_events_created_at', 'audit_events', ['created_at'])
    
    # Drop tenant-aware indexes for certificates
    op.drop_index('ix_certificates_tenant_not_after', table_name='certificates')
    op.drop_index('ix_certificates_tenant_type', table_name='certificates')
    op.drop_index('ix_certificates_tenant_common_name', table_name='certificates')
    op.drop_index('ix_certificates_tenant_status', table_name='certificates')
    op.drop_index('ix_certificates_tenant_id', table_name='certificates')
    
    # Recreate old indexes for certificates
    op.create_index('ix_certificates_certificate_type', 'certificates', ['certificate_type'])
    op.create_index('ix_certificates_common_name', 'certificates', ['common_name'])
    op.create_index('ix_certificates_status', 'certificates', ['status'])
    
    # Drop tenant-aware indexes for ca_nodes
    op.drop_index('ix_ca_nodes_tenant_status', table_name='ca_nodes')
    op.drop_index('ix_ca_nodes_tenant_type', table_name='ca_nodes')
    op.drop_index('ix_ca_nodes_tenant_id', table_name='ca_nodes')
    
    # Recreate old indexes for ca_nodes
    op.create_index('ix_ca_nodes_status', 'ca_nodes', ['status'])
    op.create_index('ix_ca_nodes_type', 'ca_nodes', ['type'])
    
    # Drop tenant_id columns
    op.drop_column('audit_events', 'tenant_id')
    op.drop_column('certificates', 'tenant_id')
    op.drop_column('ca_nodes', 'tenant_id')