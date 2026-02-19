"""Tests for the CA Engine service."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from app.services.ca_engine import (
    CaEngine,
    CaEngineError,
    InvalidKeyTypeError,
    CertificateGenerationError,
    CSRValidationError
)
from app.services.key_backend import FileKeyBackend
from app.schemas.ca import SubjectInfo
from app.schemas.certificate import SubjectAlternativeNames


class TestCaEngine:
    """Test suite for CA Engine functionality."""
    
    @pytest.fixture
    def ca_engine(self, tmp_path):
        """Create CA engine with temporary file backend."""
        key_backend = FileKeyBackend(
            storage_path=str(tmp_path / "keys"),
            encryption_password="test-password"
        )
        return CaEngine(key_backend)
    
    @pytest.fixture
    def sample_subject(self):
        """Sample subject information for certificates."""
        return SubjectInfo(
            common_name="Test CA",
            organization="Test Organization",
            organizational_unit="IT Department",
            country="US",
            state="California",
            locality="San Francisco",
            email="admin@test.com"
        )
    
    @pytest.mark.asyncio
    async def test_generate_rsa_key_pair(self, ca_engine):
        """Test RSA key pair generation."""
        key_id, private_key = await ca_engine.generate_key_pair("rsa-2048")
        
        assert key_id is not None
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048
    
    @pytest.mark.asyncio
    async def test_generate_ecdsa_key_pair(self, ca_engine):
        """Test ECDSA key pair generation."""
        key_id, private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        
        assert key_id is not None
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert private_key.curve.name == "secp256r1"
    
    @pytest.mark.asyncio
    async def test_generate_invalid_key_type(self, ca_engine):
        """Test invalid key type raises appropriate error."""
        with pytest.raises(InvalidKeyTypeError):
            await ca_engine.generate_key_pair("invalid-key-type")
    
    @pytest.mark.asyncio
    async def test_create_self_signed_certificate(self, ca_engine, sample_subject):
        """Test self-signed certificate creation."""
        # Generate key pair
        key_id, private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        
        # Create self-signed certificate
        cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="ecdsa-p256",
            is_ca=True,
            max_path_length=2
        )
        
        # Verify certificate
        assert cert_pem is not None
        assert "-----BEGIN CERTIFICATE-----" in cert_pem
        assert "-----END CERTIFICATE-----" in cert_pem
        
        # Parse and validate certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Check subject
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test CA"
        
        # Check that it's self-signed
        assert cert.issuer == cert.subject
        
        # Check CA basic constraints
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is True
        assert basic_constraints.path_length == 2
        
        # Check key usage
        key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
        assert key_usage.key_cert_sign is True
        assert key_usage.crl_sign is True
    
    @pytest.mark.asyncio
    async def test_sign_certificate(self, ca_engine, sample_subject):
        """Test certificate signing by CA."""
        # Create root CA
        ca_key_id, ca_private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        ca_cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=ca_key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="ecdsa-p256",
            is_ca=True
        )
        
        # Generate key for end-entity certificate
        _, cert_private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        
        # Create end-entity certificate subject
        cert_subject = SubjectInfo(
            common_name="test.example.com",
            organization="Test Organization",
            country="US"
        )
        
        # Create SAN
        san = SubjectAlternativeNames(
            dns=["test.example.com", "www.test.example.com"],
            ip=["192.168.1.100"]
        )
        
        # Sign certificate
        cert_pem = await ca_engine.sign_certificate(
            ca_key_id=ca_key_id,
            ca_certificate_pem=ca_cert_pem,
            subject=cert_subject,
            public_key=cert_private_key.public_key(),
            validity_days=365,
            certificate_type="server",
            subject_alternative_names=san,
            key_usage=["digital_signature", "key_encipherment"],
            extended_key_usage=["server_auth"],
            is_ca=False
        )
        
        # Verify certificate
        assert cert_pem is not None
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Check subject
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test.example.com"
        
        # Check issuer (should be the CA)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        assert cert.issuer == ca_cert.subject
        
        # Check SAN
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        
        dns_names = [name.value for name in san_ext if isinstance(name, x509.DNSName)]
        assert "test.example.com" in dns_names
        assert "www.test.example.com" in dns_names
        
        # Check basic constraints (should not be CA)
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is False
    
    @pytest.mark.asyncio
    async def test_sign_csr(self, ca_engine, sample_subject):
        """Test CSR signing."""
        # Create root CA
        ca_key_id, ca_private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        ca_cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=ca_key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="ecdsa-p256",
            is_ca=True
        )
        
        # Generate key for CSR
        _, csr_private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        
        # Create CSR
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "csr.example.com"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test Organization"),
        ]))
        
        # Add SAN to CSR
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("csr.example.com"),
                x509.DNSName("www.csr.example.com"),
            ]),
            critical=False,
        )
        
        csr = csr_builder.sign(csr_private_key, algorithm=None)  # Ed25519 uses None
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        
        # Sign CSR
        cert_pem = await ca_engine.sign_csr(
            ca_key_id=ca_key_id,
            ca_certificate_pem=ca_cert_pem,
            csr_pem=csr_pem,
            validity_days=365,
            certificate_type="server"
        )
        
        # Verify certificate
        assert cert_pem is not None
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Check subject matches CSR
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "csr.example.com"
        
        # Check SAN was preserved
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_names = [name.value for name in san_ext if isinstance(name, x509.DNSName)]
        assert "csr.example.com" in dns_names
        assert "www.csr.example.com" in dns_names
    
    @pytest.mark.asyncio
    async def test_sign_invalid_csr(self, ca_engine, sample_subject):
        """Test signing invalid CSR raises error."""
        # Create root CA
        ca_key_id, _ = await ca_engine.generate_key_pair("ecdsa-p256")
        ca_cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=ca_key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="ecdsa-p256",
            is_ca=True
        )
        
        # Invalid CSR PEM
        invalid_csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----"
        
        with pytest.raises(CSRValidationError):
            await ca_engine.sign_csr(
                ca_key_id=ca_key_id,
                ca_certificate_pem=ca_cert_pem,
                csr_pem=invalid_csr_pem,
                validity_days=365,
                certificate_type="server"
            )
    
    def test_validate_certificate_chain(self, ca_engine):
        """Test certificate chain validation."""
        # This test would require more complex setup with actual certificate chains
        # For now, test with empty chain (should return False)
        result = ca_engine.validate_certificate_chain([])
        assert result is False
    
    @pytest.mark.asyncio
    async def test_certificate_extensions(self, ca_engine, sample_subject):
        """Test various certificate extensions are properly set."""
        # Create CA
        ca_key_id, _ = await ca_engine.generate_key_pair("rsa-2048")
        ca_cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=ca_key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="rsa-2048",
            is_ca=True
        )
        
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        
        # Check Subject Key Identifier
        ski_ext = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        assert ski_ext is not None
        
        # Check Authority Key Identifier
        aki_ext = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert aki_ext is not None
        
        # For self-signed, AKI should match SKI
        assert aki_ext.value.key_identifier == ski_ext.value.digest
    
    @pytest.mark.asyncio
    async def test_different_key_types_compatibility(self, ca_engine, sample_subject):
        """Test that different key types work together."""
        # RSA CA signing ECDSA certificate
        ca_key_id, _ = await ca_engine.generate_key_pair("rsa-2048")
        ca_cert_pem = await ca_engine.create_self_signed_certificate(
            key_id=ca_key_id,
            subject=sample_subject,
            validity_years=10,
            key_type="rsa-2048",
            is_ca=True
        )
        
        # Generate ECDSA key for certificate
        _, cert_private_key = await ca_engine.generate_key_pair("ecdsa-p256")
        
        cert_subject = SubjectInfo(common_name="mixed.example.com")
        
        cert_pem = await ca_engine.sign_certificate(
            ca_key_id=ca_key_id,
            ca_certificate_pem=ca_cert_pem,
            subject=cert_subject,
            public_key=cert_private_key.public_key(),
            validity_days=365,
            certificate_type="server",
            is_ca=False
        )
        
        # Should succeed
        assert cert_pem is not None
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "mixed.example.com"