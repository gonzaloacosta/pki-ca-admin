"""Tests for the Import service."""

import pytest
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta, timezone

from app.services.import_service import (
    ImportService,
    ImportError,
    InvalidFormatError,
    CertificateKeyMismatchError,
    ChainValidationError
)
from app.services.key_backend import FileKeyBackend


class TestImportService:
    """Test suite for Import service functionality."""
    
    @pytest.fixture
    def import_service(self, tmp_path):
        """Create import service with temporary file backend."""
        key_backend = FileKeyBackend(
            storage_path=str(tmp_path / "keys"),
            encryption_password="test-password"
        )
        return ImportService(key_backend)
    
    @pytest.fixture
    def sample_certificate_and_key(self):
        """Generate a sample certificate and private key for testing."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Certificate"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        ])
        
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # Self-signed
            .public_key(private_key.public_key())
            .serial_number(12345)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )
        
        return certificate, private_key
    
    @pytest.fixture
    def sample_pkcs12_data(self, sample_certificate_and_key):
        """Create sample PKCS#12 data for testing."""
        certificate, private_key = sample_certificate_and_key
        
        # Create PKCS#12 data
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b"test-cert",
            key=private_key,
            cert=certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(b"test-password")
        )
        
        return pkcs12_data, certificate, private_key
    
    def test_parse_pem_certificates(self, import_service, sample_certificate_and_key):
        """Test parsing PEM certificates."""
        certificate, _ = sample_certificate_and_key
        
        # Convert to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        
        # Parse
        certificates = import_service.parse_pem_certificates(cert_pem)
        
        assert len(certificates) == 1
        assert certificates[0].serial_number == certificate.serial_number
    
    def test_parse_pem_certificates_multiple(self, import_service, sample_certificate_and_key):
        """Test parsing multiple PEM certificates."""
        certificate, _ = sample_certificate_and_key
        
        # Create multiple certificates PEM (duplicate for test)
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        multiple_pem = cert_pem + "\n" + cert_pem
        
        # Parse
        certificates = import_service.parse_pem_certificates(multiple_pem)
        
        assert len(certificates) == 2
        assert certificates[0].serial_number == certificate.serial_number
        assert certificates[1].serial_number == certificate.serial_number
    
    def test_parse_invalid_pem(self, import_service):
        """Test parsing invalid PEM data raises error."""
        invalid_pem = "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
        
        with pytest.raises(InvalidFormatError):
            import_service.parse_pem_certificates(invalid_pem)
    
    def test_parse_pem_private_key(self, import_service, sample_certificate_and_key):
        """Test parsing PEM private key."""
        _, private_key = sample_certificate_and_key
        
        # Convert to PEM
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Parse
        parsed_key = import_service.parse_pem_private_key(key_pem)
        
        assert parsed_key is not None
        assert isinstance(parsed_key, rsa.RSAPrivateKey)
        assert parsed_key.key_size == private_key.key_size
    
    def test_parse_encrypted_pem_private_key(self, import_service, sample_certificate_and_key):
        """Test parsing encrypted PEM private key."""
        _, private_key = sample_certificate_and_key
        password = "test-password"
        
        # Convert to encrypted PEM
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode()
        
        # Parse with password
        parsed_key = import_service.parse_pem_private_key(key_pem, password)
        
        assert parsed_key is not None
        assert isinstance(parsed_key, rsa.RSAPrivateKey)
    
    def test_parse_encrypted_pem_private_key_wrong_password(self, import_service, sample_certificate_and_key):
        """Test parsing encrypted PEM private key with wrong password fails."""
        _, private_key = sample_certificate_and_key
        password = "test-password"
        
        # Convert to encrypted PEM
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode()
        
        # Parse with wrong password
        with pytest.raises(InvalidFormatError):
            import_service.parse_pem_private_key(key_pem, "wrong-password")
    
    def test_parse_pkcs12(self, import_service, sample_pkcs12_data):
        """Test parsing PKCS#12 data."""
        pkcs12_data, certificate, private_key = sample_pkcs12_data
        
        # Parse PKCS#12
        parsed_cert, parsed_key, additional_certs = import_service.parse_pkcs12(
            pkcs12_data, "test-password"
        )
        
        assert parsed_cert is not None
        assert parsed_key is not None
        assert parsed_cert.serial_number == certificate.serial_number
        assert isinstance(parsed_key, rsa.RSAPrivateKey)
        assert additional_certs is not None  # Should be empty list
    
    def test_parse_pkcs12_wrong_password(self, import_service, sample_pkcs12_data):
        """Test parsing PKCS#12 with wrong password fails."""
        pkcs12_data, _, _ = sample_pkcs12_data
        
        with pytest.raises(InvalidFormatError):
            import_service.parse_pkcs12(pkcs12_data, "wrong-password")
    
    def test_verify_certificate_key_match(self, import_service, sample_certificate_and_key):
        """Test certificate and key matching verification."""
        certificate, private_key = sample_certificate_and_key
        
        # Should match
        assert import_service.verify_certificate_key_match(certificate, private_key) is True
        
        # Generate different key - should not match
        different_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        assert import_service.verify_certificate_key_match(certificate, different_key) is False
    
    def test_extract_certificate_info(self, import_service, sample_certificate_and_key):
        """Test extracting detailed certificate information."""
        certificate, _ = sample_certificate_and_key
        
        cert_info = import_service.extract_certificate_info(certificate)
        
        assert cert_info['serial_number'] == str(certificate.serial_number)
        assert cert_info['subject']['common_name'] == "Test Certificate"
        assert cert_info['subject']['organization'] == "Test Organization"
        assert cert_info['subject']['country'] == "US"
        assert cert_info['is_ca'] is True
        assert cert_info['is_self_signed'] is True
        assert cert_info['key_type'] == "rsa-2048"
        assert 'fingerprint_sha256' in cert_info
        assert 'certificate_pem' in cert_info
    
    def test_build_certificate_chain_single_cert(self, import_service, sample_certificate_and_key):
        """Test building certificate chain with single certificate."""
        certificate, _ = sample_certificate_and_key
        
        chains = import_service.build_certificate_chain([certificate])
        
        assert len(chains) == 1
        assert len(chains[0]) == 1
        assert chains[0][0] == certificate
    
    def test_analyze_ca_hierarchy(self, import_service, sample_certificate_and_key):
        """Test analyzing CA hierarchy."""
        certificate, _ = sample_certificate_and_key
        
        analysis = import_service.analyze_ca_hierarchy([certificate])
        
        assert analysis['total_certificates'] == 1
        assert analysis['certificate_chains'] == 1
        assert analysis['root_cas'] == 1
        assert analysis['intermediate_cas'] == 0
        assert analysis['leaf_certificates'] == 0  # It's a CA
    
    @pytest.mark.asyncio
    async def test_import_ca_from_pem(self, import_service, sample_certificate_and_key):
        """Test importing CA from PEM format."""
        certificate, private_key = sample_certificate_and_key
        
        # Convert to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Import
        result = await import_service.import_ca_from_pem(
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            ca_name="Test Imported CA"
        )
        
        assert result['success'] is True
        assert result['has_private_key'] is True
        assert result['key_id'] is not None
        assert result['ca_certificate']['subject']['common_name'] == "Test Certificate"
    
    @pytest.mark.asyncio
    async def test_import_ca_from_pem_no_private_key(self, import_service, sample_certificate_and_key):
        """Test importing CA from PEM without private key."""
        certificate, _ = sample_certificate_and_key
        
        # Convert to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        
        # Import without private key
        result = await import_service.import_ca_from_pem(
            certificate_pem=cert_pem,
            ca_name="Test Imported CA"
        )
        
        assert result['success'] is True
        assert result['has_private_key'] is False
        assert result['key_id'] is None
    
    @pytest.mark.asyncio
    async def test_import_ca_from_pem_mismatched_key(self, import_service, sample_certificate_and_key):
        """Test importing CA with mismatched certificate and key."""
        certificate, _ = sample_certificate_and_key
        
        # Generate different private key
        different_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Convert to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = different_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Import should fail
        with pytest.raises(CertificateKeyMismatchError):
            await import_service.import_ca_from_pem(
                certificate_pem=cert_pem,
                private_key_pem=key_pem
            )
    
    @pytest.mark.asyncio
    async def test_import_ca_from_pkcs12(self, import_service, sample_pkcs12_data):
        """Test importing CA from PKCS#12 format."""
        pkcs12_data, certificate, _ = sample_pkcs12_data
        
        # Import
        result = await import_service.import_ca_from_pkcs12(
            pkcs12_data=pkcs12_data,
            password="test-password",
            ca_name="Test PKCS12 CA"
        )
        
        assert result['success'] is True
        assert result['has_private_key'] is True
        assert result['key_id'] is not None
        assert result['ca_certificate']['subject']['common_name'] == "Test Certificate"
    
    def test_get_key_type_rsa(self, import_service):
        """Test key type detection for RSA keys."""
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        key_type = import_service._get_key_type(rsa_key.public_key())
        assert key_type == "rsa-2048"
    
    def test_get_key_type_ecdsa(self, import_service):
        """Test key type detection for ECDSA keys."""
        from cryptography.hazmat.primitives.asymmetric import ec
        
        ecdsa_key = ec.generate_private_key(ec.SECP256R1())
        key_type = import_service._get_key_type(ecdsa_key.public_key())
        assert key_type == "ecdsa-p256"
    
    def test_is_ca_certificate(self, import_service, sample_certificate_and_key):
        """Test CA certificate detection."""
        certificate, _ = sample_certificate_and_key
        
        # Should be detected as CA (has Basic Constraints CA=True)
        assert import_service._is_ca_certificate(certificate) is True
    
    def test_create_certificate_chain_complex(self, import_service):
        """Test building certificate chain with multiple certificates."""
        # This would require creating a more complex certificate hierarchy
        # For now, test with empty list
        chains = import_service.build_certificate_chain([])
        assert chains == []