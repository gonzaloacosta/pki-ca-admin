"""
Test cases for database models
"""

import pytest
import uuid
from datetime import datetime, timedelta
from sqlalchemy import select, exc

from app.models.database import (
    Organization,
    CertificateAuthority,
    Certificate,
    User,
    AuditEvent,
    Provisioner,
    CertificateTemplate,
    CAKeyRotation,
    CertificateLifecycleEvent
)


class TestOrganizationModel:
    """Test Organization model"""
    
    async def test_create_organization(self, test_session):
        """Test creating an organization"""
        org = Organization(
            name="ACME Corporation",
            domain="acme.com",
            plan_type="enterprise",
            max_cas=100,
            max_certificates=50000,
            alert_email="admin@acme.com",
            settings={"notifications": {"slack": True}}
        )
        
        test_session.add(org)
        await test_session.commit()
        await test_session.refresh(org)
        
        assert org.id is not None
        assert org.name == "ACME Corporation"
        assert org.domain == "acme.com"
        assert org.plan_type == "enterprise"
        assert org.settings["notifications"]["slack"] is True
        assert org.created_at is not None
        assert org.updated_at is not None

    async def test_organization_unique_domain(self, test_session):
        """Test organization domain uniqueness constraint"""
        # Create first organization
        org1 = Organization(name="ACME Corp", domain="example.com")
        test_session.add(org1)
        await test_session.commit()
        
        # Try to create second organization with same domain
        org2 = Organization(name="Another Corp", domain="example.com")
        test_session.add(org2)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()


class TestCertificateAuthorityModel:
    """Test CertificateAuthority model"""
    
    async def test_create_root_ca(self, test_session, test_organization):
        """Test creating a root CA"""
        ca = CertificateAuthority(
            organization_id=test_organization.id,
            name="Root CA",
            type="root",
            subject_dn="CN=Root CA, O=Test Organization, C=US",
            key_type="ecdsa-p256",
            key_storage="kms",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=3650),
            status="active",
            created_by="admin"
        )
        
        test_session.add(ca)
        await test_session.commit()
        await test_session.refresh(ca)
        
        assert ca.id is not None
        assert ca.type == "root"
        assert ca.parent_ca_id is None
        assert ca.organization_id == test_organization.id
        assert ca.status == "active"

    async def test_create_intermediate_ca(self, test_session, test_organization, test_root_ca):
        """Test creating an intermediate CA"""
        intermediate_ca = CertificateAuthority(
            organization_id=test_organization.id,
            name="Intermediate CA",
            type="intermediate",
            parent_ca_id=test_root_ca.id,
            subject_dn="CN=Intermediate CA, O=Test Organization, C=US",
            key_type="ecdsa-p256",
            key_storage="kms",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=1825),
            status="active",
            created_by="admin"
        )
        
        test_session.add(intermediate_ca)
        await test_session.commit()
        await test_session.refresh(intermediate_ca)
        
        assert intermediate_ca.type == "intermediate"
        assert intermediate_ca.parent_ca_id == test_root_ca.id

    async def test_ca_type_constraint(self, test_session, test_organization):
        """Test CA type constraint validation"""
        # Valid types should work
        ca_root = CertificateAuthority(
            organization_id=test_organization.id,
            name="Root CA",
            type="root",
            subject_dn="CN=Root CA",
            key_type="ecdsa-p256",
            key_storage="kms"
        )
        test_session.add(ca_root)
        await test_session.commit()
        
        # Invalid type should fail
        ca_invalid = CertificateAuthority(
            organization_id=test_organization.id,
            name="Invalid CA",
            type="invalid_type",
            subject_dn="CN=Invalid CA",
            key_type="ecdsa-p256",
            key_storage="kms"
        )
        test_session.add(ca_invalid)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()

    async def test_root_ca_no_parent_constraint(self, test_session, test_organization, test_root_ca):
        """Test that root CAs cannot have parents"""
        invalid_root = CertificateAuthority(
            organization_id=test_organization.id,
            name="Invalid Root CA",
            type="root",
            parent_ca_id=test_root_ca.id,  # This should violate constraint
            subject_dn="CN=Invalid Root CA",
            key_type="ecdsa-p256",
            key_storage="kms"
        )
        
        test_session.add(invalid_root)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()


class TestCertificateModel:
    """Test Certificate model"""
    
    async def test_create_certificate(self, test_session, test_organization, test_intermediate_ca):
        """Test creating a certificate"""
        cert = Certificate(
            ca_id=test_intermediate_ca.id,
            organization_id=test_organization.id,
            serial_number="0123456789abcdef",
            common_name="test.example.com",
            subject_dn="CN=test.example.com, O=Test Organization, C=US",
            subject_alternative_names={
                "dns": ["test.example.com", "www.test.example.com"],
                "ip": ["192.168.1.100"]
            },
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            certificate_type="server",
            key_type="ecdsa-p256",
            key_usage=["digitalSignature", "keyEncipherment"],
            extended_key_usage=["serverAuth"],
            status="active",
            requester="developer",
            request_source="api"
        )
        
        test_session.add(cert)
        await test_session.commit()
        await test_session.refresh(cert)
        
        assert cert.id is not None
        assert cert.common_name == "test.example.com"
        assert cert.status == "active"
        assert "test.example.com" in cert.subject_alternative_names["dns"]
        assert cert.ca_id == test_intermediate_ca.id

    async def test_certificate_serial_uniqueness_per_ca(self, test_session, test_organization, test_intermediate_ca):
        """Test that serial numbers must be unique per CA"""
        serial = "unique-serial-123"
        
        # Create first certificate
        cert1 = Certificate(
            ca_id=test_intermediate_ca.id,
            organization_id=test_organization.id,
            serial_number=serial,
            common_name="test1.example.com",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            certificate_type="server"
        )
        test_session.add(cert1)
        await test_session.commit()
        
        # Try to create second certificate with same serial and CA
        cert2 = Certificate(
            ca_id=test_intermediate_ca.id,
            organization_id=test_organization.id,
            serial_number=serial,  # Same serial number
            common_name="test2.example.com",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            certificate_type="server"
        )
        test_session.add(cert2)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()


class TestUserModel:
    """Test User model"""
    
    async def test_create_user(self, test_session, test_organization):
        """Test creating a user"""
        user = User(
            email="john.doe@example.com",
            organization_id=test_organization.id,
            hashed_password="$2b$12$hashed_password_here",
            full_name="John Doe",
            enabled=True,
            preferences={"theme": "dark", "notifications": {"email": True}}
        )
        
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        
        assert user.id is not None
        assert user.email == "john.doe@example.com"
        assert user.enabled is True
        assert user.preferences["theme"] == "dark"
        assert user.failed_login_attempts == 0

    async def test_user_email_uniqueness(self, test_session, test_organization):
        """Test user email uniqueness constraint"""
        email = "duplicate@example.com"
        
        # Create first user
        user1 = User(
            email=email,
            organization_id=test_organization.id,
            hashed_password="password1"
        )
        test_session.add(user1)
        await test_session.commit()
        
        # Try to create second user with same email
        user2 = User(
            email=email,  # Duplicate email
            organization_id=test_organization.id,
            hashed_password="password2"
        )
        test_session.add(user2)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()


class TestAuditEventModel:
    """Test AuditEvent model"""
    
    async def test_create_audit_event(self, test_session, test_organization, test_root_ca):
        """Test creating an audit event"""
        event = AuditEvent(
            organization_id=test_organization.id,
            event_type="ca.created",
            event_category="operational",
            severity="info",
            entity_type="ca",
            entity_id=test_root_ca.id,
            actor_type="user",
            actor_id="admin",
            actor_ip="192.168.1.100",
            event_data={
                "ca_name": test_root_ca.name,
                "ca_type": test_root_ca.type,
                "key_type": test_root_ca.key_type
            },
            request_id="req-123456789"
        )
        
        test_session.add(event)
        await test_session.commit()
        await test_session.refresh(event)
        
        assert event.id is not None
        assert event.event_type == "ca.created"
        assert event.entity_id == test_root_ca.id
        assert event.event_data["ca_name"] == test_root_ca.name
        assert event.created_at is not None


class TestProvisionerModel:
    """Test Provisioner model"""
    
    async def test_create_jwk_provisioner(self, test_session, test_organization):
        """Test creating a JWK provisioner"""
        provisioner = Provisioner(
            organization_id=test_organization.id,
            name="dev-team-jwk",
            type="JWK",
            configuration={
                "key": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "example_x_value",
                    "y": "example_y_value"
                }
            },
            claims={"maxTLSCertDuration": "24h"},
            enabled=True,
            created_by="admin"
        )
        
        test_session.add(provisioner)
        await test_session.commit()
        await test_session.refresh(provisioner)
        
        assert provisioner.id is not None
        assert provisioner.type == "JWK"
        assert provisioner.configuration["key"]["kty"] == "EC"
        assert provisioner.claims["maxTLSCertDuration"] == "24h"

    async def test_provisioner_type_constraint(self, test_session, test_organization):
        """Test provisioner type constraint"""
        # Valid type
        valid_provisioner = Provisioner(
            organization_id=test_organization.id,
            name="valid-acme",
            type="ACME",
            configuration={"directory": "/acme/directory"}
        )
        test_session.add(valid_provisioner)
        await test_session.commit()
        
        # Invalid type
        invalid_provisioner = Provisioner(
            organization_id=test_organization.id,
            name="invalid-type",
            type="INVALID_TYPE",
            configuration={}
        )
        test_session.add(invalid_provisioner)
        
        with pytest.raises(exc.IntegrityError):
            await test_session.commit()


class TestCertificateTemplateModel:
    """Test CertificateTemplate model"""
    
    async def test_create_certificate_template(self, test_session, test_organization):
        """Test creating a certificate template"""
        template = CertificateTemplate(
            organization_id=test_organization.id,
            name="server-template",
            description="Template for server certificates",
            template_data={
                "subject": {
                    "common_name": "{{ common_name }}",
                    "organization": "{{ organization }}"
                },
                "extensions": {
                    "key_usage": ["digitalSignature", "keyEncipherment"],
                    "extended_key_usage": ["serverAuth"]
                }
            },
            allowed_key_types=["rsa-2048", "ecdsa-p256"],
            max_validity_days=365,
            key_usage=["digitalSignature", "keyEncipherment"],
            extended_key_usage=["serverAuth"],
            enabled=True,
            created_by="admin"
        )
        
        test_session.add(template)
        await test_session.commit()
        await test_session.refresh(template)
        
        assert template.id is not None
        assert template.name == "server-template"
        assert "digitalSignature" in template.key_usage
        assert template.max_validity_days == 365


class TestCAKeyRotationModel:
    """Test CAKeyRotation model"""
    
    async def test_create_key_rotation_record(self, test_session, test_root_ca):
        """Test creating a key rotation record"""
        rotation = CAKeyRotation(
            ca_id=test_root_ca.id,
            old_key_id="arn:aws:kms:us-east-1:123456:key/old-key-id",
            new_key_id="arn:aws:kms:us-east-1:123456:key/new-key-id",
            rotation_reason="scheduled_rotation",
            initiated_by="admin",
            completed_at=datetime.utcnow()
        )
        
        test_session.add(rotation)
        await test_session.commit()
        await test_session.refresh(rotation)
        
        assert rotation.id is not None
        assert rotation.ca_id == test_root_ca.id
        assert rotation.rotation_reason == "scheduled_rotation"
        assert rotation.completed_at is not None


class TestCertificateLifecycleEventModel:
    """Test CertificateLifecycleEvent model"""
    
    async def test_create_lifecycle_event(self, test_session, test_certificate):
        """Test creating a certificate lifecycle event"""
        event = CertificateLifecycleEvent(
            certificate_id=test_certificate.id,
            event_type="issued",
            event_data={
                "issuance_method": "api",
                "requester": "developer",
                "template_used": "server-template"
            }
        )
        
        test_session.add(event)
        await test_session.commit()
        await test_session.refresh(event)
        
        assert event.id is not None
        assert event.certificate_id == test_certificate.id
        assert event.event_type == "issued"
        assert event.event_data["issuance_method"] == "api"


class TestModelRelationships:
    """Test model relationships"""
    
    async def test_organization_ca_relationship(self, test_session, test_organization, test_root_ca):
        """Test Organization -> CertificateAuthority relationship"""
        # Load organization with CAs
        result = await test_session.execute(
            select(Organization).where(Organization.id == test_organization.id)
        )
        org = result.scalar_one()
        
        # Access related CAs (this will trigger lazy loading)
        cas = org.certificate_authorities
        
        # Should contain our test CA
        ca_ids = [ca.id for ca in cas]
        assert test_root_ca.id in ca_ids

    async def test_ca_certificate_relationship(self, test_session, test_intermediate_ca, test_certificate):
        """Test CertificateAuthority -> Certificate relationship"""
        # Load CA with certificates
        result = await test_session.execute(
            select(CertificateAuthority).where(CertificateAuthority.id == test_intermediate_ca.id)
        )
        ca = result.scalar_one()
        
        # Access related certificates
        certificates = ca.certificates
        
        # Should contain our test certificate
        cert_ids = [cert.id for cert in certificates]
        assert test_certificate.id in cert_ids

    async def test_ca_hierarchy_relationship(self, test_session, test_root_ca, test_intermediate_ca):
        """Test parent-child CA relationship"""
        # Load intermediate CA
        result = await test_session.execute(
            select(CertificateAuthority).where(CertificateAuthority.id == test_intermediate_ca.id)
        )
        intermediate = result.scalar_one()
        
        # Check parent relationship
        assert intermediate.parent_ca_id == test_root_ca.id
        
        # Access parent CA
        parent = intermediate.parent_ca
        assert parent.id == test_root_ca.id
        assert parent.type == "root"