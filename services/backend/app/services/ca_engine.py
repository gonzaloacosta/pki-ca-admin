"""
Certificate Authority Engine - Core cryptographic operations.
Pure Python implementation using the cryptography library.
"""

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Union, Tuple
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes, 
    PublicKeyTypes,
    CertificateIssuerPrivateKeyTypes
)

from app.services.key_backend import KeyBackend, get_key_backend
from app.schemas.ca import SubjectInfo
from app.schemas.certificate import SubjectAlternativeNames


class CaEngineError(Exception):
    """Base exception for CA Engine operations."""
    pass


class InvalidKeyTypeError(CaEngineError):
    """Invalid key type specified."""
    pass


class CertificateGenerationError(CaEngineError):
    """Error during certificate generation."""
    pass


class CSRValidationError(CaEngineError):
    """Error validating Certificate Signing Request."""
    pass


class CaEngine:
    """
    Certificate Authority Engine for cryptographic operations.
    
    Handles:
    - Key pair generation
    - Self-signed certificate creation (root CAs)
    - Certificate signing (intermediate CAs and end-entity certificates)
    - CSR processing
    - Certificate chain building and validation
    """
    
    def __init__(self, key_backend: Optional[KeyBackend] = None):
        """
        Initialize CA Engine.
        
        Args:
            key_backend: Key storage backend (defaults to configured backend)
        """
        self.key_backend = key_backend or get_key_backend()
    
    async def generate_key_pair(self, key_type: str) -> Tuple[str, PrivateKeyTypes]:
        """
        Generate a new key pair and store it securely.
        
        Args:
            key_type: Type of key to generate (rsa-2048, ecdsa-p256, ed25519, etc.)
            
        Returns:
            Tuple[str, PrivateKey]: (key_id, private_key_object)
            
        Raises:
            InvalidKeyTypeError: If key type is not supported
            CaEngineError: If key generation fails
        """
        try:
            if key_type == "rsa-2048":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
            elif key_type == "rsa-3072":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=3072
                )
            elif key_type == "rsa-4096":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096
                )
            elif key_type == "ecdsa-p256":
                private_key = ec.generate_private_key(ec.SECP256R1())
            elif key_type == "ecdsa-p384":
                private_key = ec.generate_private_key(ec.SECP384R1())
            elif key_type == "ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise InvalidKeyTypeError(f"Unsupported key type: {key_type}")
            
            # Store the key and get the key ID
            key_id = await self.key_backend.store_private_key(private_key, f"ca-key-{uuid.uuid4()}")
            
            return key_id, private_key
            
        except Exception as e:
            if isinstance(e, InvalidKeyTypeError):
                raise
            raise CaEngineError(f"Failed to generate key pair: {str(e)}")
    
    async def create_self_signed_certificate(
        self,
        key_id: str,
        subject: SubjectInfo,
        validity_years: int = 10,
        key_type: str = "ecdsa-p256",
        is_ca: bool = True,
        max_path_length: Optional[int] = None
    ) -> str:
        """
        Create a self-signed certificate (typically for root CAs).
        
        Args:
            key_id: Identifier for the private key
            subject: Certificate subject information
            validity_years: Certificate validity period in years
            key_type: Type of key being used
            is_ca: Whether this is a CA certificate
            max_path_length: Maximum path length for CA certificates
            
        Returns:
            str: PEM-encoded certificate
            
        Raises:
            CertificateGenerationError: If certificate generation fails
        """
        try:
            # Load the private key
            private_key = await self.key_backend.load_private_key(key_id)
            
            # Build the subject name
            subject_name = self._build_x509_name(subject)
            
            # Create certificate builder
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject_name)
            builder = builder.issuer_name(subject_name)  # Self-signed
            builder = builder.public_key(private_key.public_key())
            
            # Set validity period
            now = datetime.now(timezone.utc)
            builder = builder.not_valid_before(now)
            builder = builder.not_valid_after(now + timedelta(days=validity_years * 365))
            
            # Generate a random serial number
            serial_number = int.from_bytes(hashlib.sha256(
                f"{subject.common_name}-{now.isoformat()}".encode()
            ).digest()[:8], byteorder='big')
            builder = builder.serial_number(serial_number)
            
            # Add extensions
            if is_ca:
                # Basic Constraints for CA
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=True, path_length=max_path_length),
                    critical=True,
                )
                
                # Key Usage for CA
                builder = builder.add_extension(
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
            
            # Subject Key Identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            
            # Authority Key Identifier (same as subject for self-signed)
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
                critical=False,
            )
            
            # Sign the certificate
            hash_algorithm = self._get_hash_algorithm(key_type)
            certificate = builder.sign(private_key, hash_algorithm)
            
            # Return PEM-encoded certificate
            return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
        except Exception as e:
            raise CertificateGenerationError(f"Failed to create self-signed certificate: {str(e)}")
    
    async def sign_certificate(
        self,
        ca_key_id: str,
        ca_certificate_pem: str,
        subject: SubjectInfo,
        public_key: PublicKeyTypes,
        validity_days: int = 365,
        certificate_type: str = "server",
        subject_alternative_names: Optional[SubjectAlternativeNames] = None,
        key_usage: Optional[List[str]] = None,
        extended_key_usage: Optional[List[str]] = None,
        is_ca: bool = False,
        max_path_length: Optional[int] = None
    ) -> str:
        """
        Sign a certificate using a CA.
        
        Args:
            ca_key_id: CA private key identifier
            ca_certificate_pem: CA certificate in PEM format
            subject: Certificate subject information
            public_key: Subject's public key
            validity_days: Certificate validity in days
            certificate_type: Type of certificate (server, client, etc.)
            subject_alternative_names: Subject Alternative Names
            key_usage: Key usage extensions
            extended_key_usage: Extended key usage extensions
            is_ca: Whether this is a CA certificate
            max_path_length: Path length constraint for CA certificates
            
        Returns:
            str: PEM-encoded certificate
            
        Raises:
            CertificateGenerationError: If certificate generation fails
        """
        try:
            # Load CA private key and certificate
            ca_private_key = await self.key_backend.load_private_key(ca_key_id)
            ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode())
            
            # Build subject name
            subject_name = self._build_x509_name(subject)
            
            # Create certificate builder
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject_name)
            builder = builder.issuer_name(ca_certificate.subject)
            builder = builder.public_key(public_key)
            
            # Set validity period
            now = datetime.now(timezone.utc)
            builder = builder.not_valid_before(now)
            builder = builder.not_valid_after(now + timedelta(days=validity_days))
            
            # Generate serial number
            serial_number = int.from_bytes(hashlib.sha256(
                f"{subject.common_name}-{now.isoformat()}".encode()
            ).digest()[:8], byteorder='big')
            builder = builder.serial_number(serial_number)
            
            # Add Subject Alternative Names
            if subject_alternative_names:
                san_list = []
                
                for dns_name in subject_alternative_names.dns or []:
                    san_list.append(x509.DNSName(dns_name))
                
                for ip_addr in subject_alternative_names.ip or []:
                    san_list.append(x509.IPAddress(ipaddress.ip_address(ip_addr)))
                
                for email in subject_alternative_names.email or []:
                    san_list.append(x509.RFC822Name(str(email)))
                
                for uri in subject_alternative_names.uri or []:
                    san_list.append(x509.UniformResourceIdentifier(uri))
                
                if san_list:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False,
                    )
            
            # Add Basic Constraints
            if is_ca:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=True, path_length=max_path_length),
                    critical=True,
                )
            else:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
            
            # Add Key Usage
            key_usage_ext = self._build_key_usage(key_usage, certificate_type, is_ca)
            if key_usage_ext:
                builder = builder.add_extension(key_usage_ext, critical=True)
            
            # Add Extended Key Usage
            ext_key_usage_ext = self._build_extended_key_usage(extended_key_usage, certificate_type)
            if ext_key_usage_ext:
                builder = builder.add_extension(ext_key_usage_ext, critical=False)
            
            # Subject Key Identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            
            # Authority Key Identifier
            try:
                authority_key_id = ca_certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value.digest
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier(
                        key_identifier=authority_key_id,
                        authority_cert_issuer=None,
                        authority_cert_serial_number=None,
                    ),
                    critical=False,
                )
            except x509.ExtensionNotFound:
                # Fallback to using public key
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
                    critical=False,
                )
            
            # Sign the certificate
            hash_algorithm = self._get_hash_algorithm_for_key(ca_private_key)
            certificate = builder.sign(ca_private_key, hash_algorithm)
            
            return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
        except Exception as e:
            raise CertificateGenerationError(f"Failed to sign certificate: {str(e)}")
    
    async def sign_csr(
        self,
        ca_key_id: str,
        ca_certificate_pem: str,
        csr_pem: str,
        validity_days: int = 365,
        certificate_type: str = "server",
        subject_alternative_names: Optional[SubjectAlternativeNames] = None,
        key_usage: Optional[List[str]] = None,
        extended_key_usage: Optional[List[str]] = None
    ) -> str:
        """
        Sign a Certificate Signing Request (CSR).
        
        Args:
            ca_key_id: CA private key identifier
            ca_certificate_pem: CA certificate in PEM format
            csr_pem: Certificate Signing Request in PEM format
            validity_days: Certificate validity in days
            certificate_type: Type of certificate
            subject_alternative_names: Optional SAN override
            key_usage: Optional key usage override
            extended_key_usage: Optional extended key usage override
            
        Returns:
            str: PEM-encoded certificate
            
        Raises:
            CSRValidationError: If CSR is invalid
            CertificateGenerationError: If certificate generation fails
        """
        try:
            # Load and validate CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            
            # Verify CSR signature
            if not csr.is_signature_valid:
                raise CSRValidationError("CSR signature is invalid")
            
            # Extract subject from CSR
            subject_name = csr.subject
            
            # Convert to our SubjectInfo format
            subject = SubjectInfo(
                common_name=subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                organization=self._get_name_attribute(subject_name, NameOID.ORGANIZATION_NAME),
                organizational_unit=self._get_name_attribute(subject_name, NameOID.ORGANIZATIONAL_UNIT_NAME),
                country=self._get_name_attribute(subject_name, NameOID.COUNTRY_NAME),
                state=self._get_name_attribute(subject_name, NameOID.STATE_OR_PROVINCE_NAME),
                locality=self._get_name_attribute(subject_name, NameOID.LOCALITY_NAME),
                email=self._get_name_attribute(subject_name, NameOID.EMAIL_ADDRESS),
            )
            
            # Extract SAN from CSR if not provided
            if subject_alternative_names is None:
                try:
                    san_ext = csr.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    ).value
                    subject_alternative_names = self._extract_san_from_extension(san_ext)
                except x509.ExtensionNotFound:
                    pass
            
            # Sign the certificate
            return await self.sign_certificate(
                ca_key_id=ca_key_id,
                ca_certificate_pem=ca_certificate_pem,
                subject=subject,
                public_key=csr.public_key(),
                validity_days=validity_days,
                certificate_type=certificate_type,
                subject_alternative_names=subject_alternative_names,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                is_ca=False
            )
            
        except x509.InvalidSignature:
            raise CSRValidationError("Invalid CSR signature")
        except Exception as e:
            if isinstance(e, (CSRValidationError, CertificateGenerationError)):
                raise
            raise CertificateGenerationError(f"Failed to sign CSR: {str(e)}")
    
    def validate_certificate_chain(self, certificate_chain_pem: List[str]) -> bool:
        """
        Validate a certificate chain.
        
        Args:
            certificate_chain_pem: List of PEM certificates (leaf first)
            
        Returns:
            bool: True if chain is valid
        """
        try:
            certificates = [
                x509.load_pem_x509_certificate(cert_pem.encode())
                for cert_pem in certificate_chain_pem
            ]
            
            # Basic validation - check that each certificate is signed by the next
            for i in range(len(certificates) - 1):
                cert = certificates[i]
                issuer_cert = certificates[i + 1]
                
                # Check if issuer matches
                if cert.issuer != issuer_cert.subject:
                    return False
                
                # Verify signature
                try:
                    issuer_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        cert.signature_algorithm_oid._name.replace('_', '')
                    )
                except Exception:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _build_x509_name(self, subject: SubjectInfo) -> x509.Name:
        """Build X.509 Name from SubjectInfo."""
        name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, subject.common_name),
        ]
        
        if subject.organization:
            name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization)
            )
        
        if subject.organizational_unit:
            name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit)
            )
        
        if subject.country:
            name_attributes.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country)
            )
        
        if subject.state:
            name_attributes.append(
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.state)
            )
        
        if subject.locality:
            name_attributes.append(
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality)
            )
        
        if subject.email:
            name_attributes.append(
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject.email)
            )
        
        return x509.Name(name_attributes)
    
    def _get_name_attribute(self, name: x509.Name, oid: x509.NameOID) -> Optional[str]:
        """Extract name attribute by OID."""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, KeyError):
            return None
    
    def _extract_san_from_extension(self, san_ext: x509.SubjectAlternativeName) -> SubjectAlternativeNames:
        """Extract SAN from X.509 extension."""
        dns_names = []
        ip_addresses = []
        emails = []
        uris = []
        
        for name in san_ext:
            if isinstance(name, x509.DNSName):
                dns_names.append(name.value)
            elif isinstance(name, x509.IPAddress):
                ip_addresses.append(str(name.value))
            elif isinstance(name, x509.RFC822Name):
                emails.append(name.value)
            elif isinstance(name, x509.UniformResourceIdentifier):
                uris.append(name.value)
        
        return SubjectAlternativeNames(
            dns=dns_names or None,
            ip=ip_addresses or None,
            email=emails or None,
            uri=uris or None
        )
    
    def _build_key_usage(
        self, 
        key_usage: Optional[List[str]], 
        certificate_type: str, 
        is_ca: bool
    ) -> Optional[x509.KeyUsage]:
        """Build Key Usage extension."""
        if is_ca:
            return x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            )
        
        # Default key usage based on certificate type
        usage_map = {
            'server': ['digital_signature', 'key_encipherment'],
            'client': ['digital_signature'],
            'email': ['digital_signature', 'content_commitment', 'key_encipherment'],
            'codesigning': ['digital_signature'],
            'timestamping': ['digital_signature']
        }
        
        if not key_usage:
            key_usage = usage_map.get(certificate_type, ['digital_signature'])
        
        return x509.KeyUsage(
            digital_signature='digital_signature' in key_usage,
            content_commitment='content_commitment' in key_usage,
            key_encipherment='key_encipherment' in key_usage,
            data_encipherment='data_encipherment' in key_usage,
            key_agreement='key_agreement' in key_usage,
            key_cert_sign='key_cert_sign' in key_usage,
            crl_sign='crl_sign' in key_usage,
            encipher_only='encipher_only' in key_usage,
            decipher_only='decipher_only' in key_usage,
        )
    
    def _build_extended_key_usage(
        self,
        extended_key_usage: Optional[List[str]],
        certificate_type: str
    ) -> Optional[x509.ExtendedKeyUsage]:
        """Build Extended Key Usage extension."""
        # Default extended key usage based on certificate type
        usage_map = {
            'server': ['server_auth'],
            'client': ['client_auth'],
            'email': ['email_protection'],
            'codesigning': ['code_signing'],
            'timestamping': ['time_stamping']
        }
        
        if not extended_key_usage:
            extended_key_usage = usage_map.get(certificate_type, [])
        
        if not extended_key_usage:
            return None
        
        eku_oids = []
        eku_map = {
            'server_auth': ExtendedKeyUsageOID.SERVER_AUTH,
            'client_auth': ExtendedKeyUsageOID.CLIENT_AUTH,
            'code_signing': ExtendedKeyUsageOID.CODE_SIGNING,
            'email_protection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
            'time_stamping': ExtendedKeyUsageOID.TIME_STAMPING,
            'ocsp_signing': ExtendedKeyUsageOID.OCSP_SIGNING,
            'any_extended_key_usage': ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        }
        
        for usage in extended_key_usage:
            if usage in eku_map:
                eku_oids.append(eku_map[usage])
        
        return x509.ExtendedKeyUsage(eku_oids) if eku_oids else None
    
    def _get_hash_algorithm(self, key_type: str):
        """Get appropriate hash algorithm for key type."""
        if key_type.startswith('rsa'):
            return hashes.SHA256()
        elif key_type.startswith('ecdsa'):
            return hashes.SHA256()
        elif key_type == 'ed25519':
            return None  # Ed25519 uses its own hash
        else:
            return hashes.SHA256()
    
    def _get_hash_algorithm_for_key(self, private_key: PrivateKeyTypes):
        """Get appropriate hash algorithm for a private key."""
        if isinstance(private_key, rsa.RSAPrivateKey):
            return hashes.SHA256()
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            return hashes.SHA256()
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            return None
        else:
            return hashes.SHA256()