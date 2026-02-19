"""
Test cases for Certificate Authority service
"""

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from app.services.ca_service import (
    create_certificate_authority,
    update_certificate_authority,
    revoke_certificate_authority,
    check_ca_renewal_needed,
    _build_subject_dn
)
from app.models.schemas import CACreate, CAUpdate, CASubject, CAType, KeyType, KeyStorage, CAPolicy
from app.models.database import CertificateAuthority


class TestCAService:
    """Test Certificate Authority service operations"""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        return session
    
    @pytest.fixture
    def sample_ca_create_data(self):
        """Sample CA creation data"""
        return CACreate(
            name="Test Root CA",
            description="Test Root Certificate Authority",
            type=CAType.root,
            subject=CASubject(
                common_name="Test Root CA",
                organization="Test Organization",
                organizational_unit="IT Security",
                country="US",
                state="California",
                locality="San Francisco"
            ),
            key_type=KeyType.ecdsa_p256,
            key_storage=KeyStorage.kms,
            validity_years=10,
            auto_renewal=True,
            renewal_threshold_days=30,
            metadata={"purpose": "testing"}
        )
    
    @pytest.fixture
    def sample_ca_instance(self):
        """Sample CA database instance"""
        return CertificateAuthority(
            id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            name="Test Root CA",
            type="root",
            subject_dn="CN=Test Root CA, OU=IT Security, O=Test Organization, L=San Francisco, ST=California, C=US",
            key_type="ecdsa-p256",
            key_storage="kms",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=3650),
            auto_renewal=True,
            renewal_threshold_days=30,
            status="active",
            created_by="test-user"
        )

    async def test_create_certificate_authority(self, mock_db_session, sample_ca_create_data):
        """Test CA creation"""
        organization_id = uuid.uuid4()
        created_by = "test-user"
        
        # Mock database operations
        mock_db_session.add = AsyncMock()
        mock_db_session.flush = AsyncMock()
        
        # Create CA
        ca = await create_certificate_authority(
            db=mock_db_session,
            organization_id=organization_id,
            ca_data=sample_ca_create_data,
            created_by=created_by
        )
        
        # Assertions
        assert ca.organization_id == organization_id
        assert ca.name == sample_ca_create_data.name
        assert ca.type == sample_ca_create_data.type.value
        assert ca.key_type == sample_ca_create_data.key_type.value
        assert ca.key_storage == sample_ca_create_data.key_storage.value
        assert ca.created_by == created_by
        assert ca.status == "active"  # Should be set by mock crypto operations
        assert ca.serial_number is not None
        assert ca.certificate_pem is not None
        
        # Verify database operations were called
        mock_db_session.add.assert_called_once()
        mock_db_session.flush.assert_called_once()

    async def test_update_certificate_authority(self, mock_db_session, sample_ca_instance):
        """Test CA update"""
        update_data = CAUpdate(
            name="Updated CA Name",
            description="Updated description",
            auto_renewal=False,
            renewal_threshold_days=60
        )
        
        # Mock database operations
        mock_db_session.execute = AsyncMock()
        mock_db_session.refresh = AsyncMock()
        
        # Update CA
        updated_ca = await update_certificate_authority(
            db=mock_db_session,
            ca=sample_ca_instance,
            ca_update=update_data
        )
        
        # Verify update was called
        mock_db_session.execute.assert_called_once()
        mock_db_session.refresh.assert_called_once()

    async def test_revoke_certificate_authority(self, mock_db_session, sample_ca_instance):
        """Test CA revocation"""
        reason = "key_compromise"
        revoked_by = "admin-user"
        
        # Revoke CA
        revoked_ca = await revoke_certificate_authority(
            db=mock_db_session,
            ca=sample_ca_instance,
            reason=reason,
            revoked_by=revoked_by
        )
        
        # Assertions
        assert revoked_ca.status == "revoked"
        assert "revoked_at" in revoked_ca.metadata
        assert revoked_ca.metadata["revoked_by"] == revoked_by
        assert revoked_ca.metadata["revocation_reason"] == reason

    async def test_check_ca_renewal_needed_true(self, mock_db_session, sample_ca_instance):
        """Test CA renewal check when renewal is needed"""
        # Set expiry within renewal threshold
        sample_ca_instance.not_after = datetime.utcnow() + timedelta(days=15)
        sample_ca_instance.renewal_threshold_days = 30
        sample_ca_instance.auto_renewal = True
        
        needs_renewal = await check_ca_renewal_needed(mock_db_session, sample_ca_instance)
        assert needs_renewal is True

    async def test_check_ca_renewal_needed_false(self, mock_db_session, sample_ca_instance):
        """Test CA renewal check when renewal is not needed"""
        # Set expiry beyond renewal threshold
        sample_ca_instance.not_after = datetime.utcnow() + timedelta(days=365)
        sample_ca_instance.renewal_threshold_days = 30
        sample_ca_instance.auto_renewal = True
        
        needs_renewal = await check_ca_renewal_needed(mock_db_session, sample_ca_instance)
        assert needs_renewal is False

    async def test_check_ca_renewal_disabled(self, mock_db_session, sample_ca_instance):
        """Test CA renewal check when auto-renewal is disabled"""
        sample_ca_instance.not_after = datetime.utcnow() + timedelta(days=15)
        sample_ca_instance.renewal_threshold_days = 30
        sample_ca_instance.auto_renewal = False
        
        needs_renewal = await check_ca_renewal_needed(mock_db_session, sample_ca_instance)
        assert needs_renewal is False

    def test_build_subject_dn_complete(self):
        """Test subject DN building with all components"""
        subject = CASubject(
            common_name="Test CA",
            organizational_unit="IT Security",
            organization="Test Org",
            locality="San Francisco",
            state="California",
            country="US",
            email="admin@test.org"
        )
        
        dn = _build_subject_dn(subject)
        expected = "CN=Test CA, OU=IT Security, O=Test Org, L=San Francisco, ST=California, C=US, emailAddress=admin@test.org"
        assert dn == expected

    def test_build_subject_dn_minimal(self):
        """Test subject DN building with minimal components"""
        subject = CASubject(
            common_name="Test CA",
            organization="Test Org",
            country="US"
        )
        
        dn = _build_subject_dn(subject)
        expected = "CN=Test CA, O=Test Org, C=US"
        assert dn == expected

    def test_build_subject_dn_empty(self):
        """Test subject DN building with no components"""
        subject = CASubject()
        
        dn = _build_subject_dn(subject)
        assert dn == ""


@pytest.mark.asyncio
class TestCAServiceIntegration:
    """Integration tests for CA service with real database operations"""
    
    # TODO: Add integration tests with actual database
    # These would test the full flow including database constraints,
    # foreign key relationships, and transaction handling
    
    async def test_create_root_ca_integration(self):
        """Integration test for root CA creation"""
        # TODO: Implement with test database
        pass
    
    async def test_create_intermediate_ca_integration(self):
        """Integration test for intermediate CA creation"""
        # TODO: Implement with test database
        pass
    
    async def test_ca_hierarchy_constraints(self):
        """Test database constraints for CA hierarchy"""
        # TODO: Test that root CAs cannot have parents
        # TODO: Test that intermediate CAs must have parents
        pass


# Test data fixtures
@pytest.fixture
def sample_root_ca_config():
    """Sample configuration for root CA"""
    return {
        "name": "ACME Corp Root CA",
        "type": "root",
        "subject": {
            "common_name": "ACME Corp Root CA",
            "organization": "ACME Corporation",
            "organizational_unit": "PKI Services",
            "country": "US",
            "state": "Delaware",
            "locality": "Wilmington"
        },
        "key_type": "ecdsa-p384",
        "key_storage": "kms",
        "validity_years": 20,
        "policy": {
            "max_path_length": 2,
            "allowed_key_types": ["rsa-2048", "ecdsa-p256", "ecdsa-p384"],
            "max_validity_days": 3650
        }
    }


@pytest.fixture  
def sample_intermediate_ca_config():
    """Sample configuration for intermediate CA"""
    return {
        "name": "ACME Corp Development CA",
        "type": "intermediate", 
        "subject": {
            "common_name": "ACME Corp Development CA",
            "organization": "ACME Corporation",
            "organizational_unit": "Development Environment",
            "country": "US"
        },
        "key_type": "ecdsa-p256",
        "key_storage": "kms",
        "validity_years": 5,
        "policy": {
            "max_path_length": 0,
            "allowed_key_types": ["rsa-2048", "ecdsa-p256"], 
            "max_validity_days": 365
        }
    }