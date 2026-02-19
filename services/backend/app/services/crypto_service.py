"""
Real cryptographic service for PKI operations

This replaces the mock crypto operations with real certificate generation
using the Python cryptography library.
"""

import uuid
import secrets
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any, Optional
from ipaddress import IPv4Address, IPv6Address

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from app.models.database import CertificateAuthority, Certificate
from app.models.schemas import KeyType, CertificateRequest, CSRSigningRequest
from app.services.kms_service import get_kms_service, KMSException


class CryptographicService:
    """Real cryptographic operations for PKI"""
    
    def __init__(self):
        self.hash_algorithm = hashes.SHA256()
        self.kms_service = get_kms_service()
    
    def generate_private_key(self, key_type: str) -> PrivateKeyTypes:
        """
        Generate a private key based on the specified type
        
        Args:
            key_type: Key type (rsa-2048, ecdsa-p256, etc.)
            
        Returns:
            Private key instance
        """
        if key_type == "rsa-2048":
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        elif key_type == "rsa-4096":
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
        elif key_type == "ecdsa-p256":
            return ec.generate_private_key(ec.SECP256R1())
        elif key_type == "ecdsa-p384":
            return ec.generate_private_key(ec.SECP384R1())
        elif key_type == "ed25519":
            return ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
    
    def parse_subject_dn(self, subject_dn: str) -> x509.Name:
        """
        Parse subject DN string into x509.Name object
        
        Args:
            subject_dn: Subject DN string like "CN=Test CA, O=Test Org, C=US"
            
        Returns:
            x509.Name object
        """
        name_attributes = []
        
        # Parse DN components
        dn_parts = [part.strip() for part in subject_dn.split(',')]
        
        for part in dn_parts:
            if '=' not in part:
                continue
                
            attr_name, attr_value = part.split('=', 1)
            attr_name = attr_name.strip().upper()
            attr_value = attr_value.strip()
            
            # Map common DN attributes to OIDs
            if attr_name == 'CN':
                oid = NameOID.COMMON_NAME
            elif attr_name == 'O':
                oid = NameOID.ORGANIZATION_NAME
            elif attr_name == 'OU':
                oid = NameOID.ORGANIZATIONAL_UNIT_NAME
            elif attr_name == 'C':
                oid = NameOID.COUNTRY_NAME
            elif attr_name == 'ST' or attr_name == 'S':
                oid = NameOID.STATE_OR_PROVINCE_NAME
            elif attr_name == 'L':
                oid = NameOID.LOCALITY_NAME
            elif attr_name in ['EMAIL', 'EMAILADDRESS']:
                oid = NameOID.EMAIL_ADDRESS
            else:
                # Skip unknown attributes
                continue
            
            name_attributes.append(x509.NameAttribute(oid, attr_value))
        
        return x509.Name(name_attributes)
    
    def generate_ca_certificate(
        self, 
        ca: CertificateAuthority,
        private_key: PrivateKeyTypes,
        issuer_ca: Optional[CertificateAuthority] = None,
        issuer_private_key: Optional[PrivateKeyTypes] = None
    ) -> x509.Certificate:
        """
        Generate a CA certificate
        
        Args:
            ca: CA database object
            private_key: Private key for the CA
            issuer_ca: Issuer CA (None for self-signed root)
            issuer_private_key: Issuer's private key (None for self-signed root)
            
        Returns:
            X.509 certificate
        """
        subject = self.parse_subject_dn(ca.subject_dn)
        
        # For self-signed root CAs, subject == issuer
        if issuer_ca is None:
            issuer = subject
            signing_key = private_key
        else:
            issuer = self.parse_subject_dn(issuer_ca.subject_dn)
            signing_key = issuer_private_key
            
        if signing_key is None:
            raise ValueError("Signing key is required")
        
        # Generate serial number
        serial_number = x509.random_serial_number()
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(ca.not_before or datetime.utcnow())
        builder = builder.not_valid_after(ca.not_after or datetime.utcnow() + timedelta(days=3650))
        
        # Add CA extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=ca.max_path_length),
            critical=True
        )
        
        # Key usage for CAs
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Authority Key Identifier (for intermediate CAs)
        if issuer_ca is not None and issuer_private_key is not None:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()),
                critical=False
            )
        
        # CRL Distribution Points (if configured)
        if ca.crl_distribution_points:
            distribution_points = []
            for url in ca.crl_distribution_points:
                distribution_points.append(
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None
                    )
                )
            builder = builder.add_extension(
                x509.CRLDistributionPoints(distribution_points),
                critical=False
            )
        
        # OCSP Responder (if configured)
        if ca.ocsp_responder_url:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ca.ocsp_responder_url)
                    )
                ]),
                critical=False
            )
        
        # Sign the certificate
        certificate = builder.sign(signing_key, self.hash_algorithm)
        
        return certificate
    
    def generate_end_entity_certificate(
        self,
        cert_request: CertificateRequest,
        ca: CertificateAuthority,
        ca_private_key: PrivateKeyTypes,
        ca_certificate: x509.Certificate
    ) -> Tuple[x509.Certificate, PrivateKeyTypes]:
        """
        Generate an end-entity certificate
        
        Args:
            cert_request: Certificate request details
            ca: Issuing CA
            ca_private_key: CA's private key
            ca_certificate: CA's certificate
            
        Returns:
            Tuple of (certificate, private_key)
        """
        # Generate private key for the certificate
        private_key = self.generate_private_key(cert_request.key_type.value)
        
        # Build subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cert_request.common_name)
        ])
        
        # Get issuer from CA certificate
        issuer = ca_certificate.subject
        
        # Generate serial number
        serial_number = x509.random_serial_number()
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.utcnow() + timedelta(days=cert_request.validity_days)
        )
        
        # Add Subject Alternative Names if provided
        if cert_request.subject_alternative_names:
            san_list = []
            
            # DNS names
            for dns_name in cert_request.subject_alternative_names.dns:
                san_list.append(x509.DNSName(dns_name))
            
            # IP addresses
            for ip in cert_request.subject_alternative_names.ip:
                if isinstance(ip, (IPv4Address, IPv6Address)):
                    san_list.append(x509.IPAddress(ip))
                else:
                    # Parse string IP addresses - try IPv4 first, then IPv6
                    try:
                        san_list.append(x509.IPAddress(IPv4Address(ip)))
                    except ValueError:
                        try:
                            san_list.append(x509.IPAddress(IPv6Address(ip)))
                        except ValueError:
                            raise ValueError(f"Invalid IP address: {ip}")
            
            # Email addresses
            for email in cert_request.subject_alternative_names.email:
                san_list.append(x509.RFC822Name(email))
            
            # URIs
            for uri in cert_request.subject_alternative_names.uri:
                san_list.append(x509.UniformResourceIdentifier(uri))
            
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
        
        # Add Key Usage
        key_usage_map = {
            'digitalSignature': 'digital_signature',
            'keyEncipherment': 'key_encipherment',
            'dataEncipherment': 'data_encipherment',
            'keyAgreement': 'key_agreement',
            'keyCertSign': 'key_cert_sign',
            'crlSign': 'crl_sign',
            'encipherOnly': 'encipher_only',
            'decipherOnly': 'decipher_only'
        }
        
        key_usage_kwargs = {attr: False for attr in key_usage_map.values()}
        key_usage_kwargs['content_commitment'] = False  # Always False by default
        
        for usage in cert_request.key_usage:
            if usage in key_usage_map:
                key_usage_kwargs[key_usage_map[usage]] = True
        
        builder = builder.add_extension(
            x509.KeyUsage(**key_usage_kwargs),
            critical=True
        )
        
        # Add Extended Key Usage
        eku_oids = []
        eku_map = {
            'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
            'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
            'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
            'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
            'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
            'ocspSigning': ExtendedKeyUsageOID.OCSP_SIGNING
        }
        
        for eku in cert_request.extended_key_usage:
            if eku in eku_map:
                eku_oids.append(eku_map[eku])
        
        if eku_oids:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(eku_oids),
                critical=False
            )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False
        )
        
        # Sign the certificate
        certificate = builder.sign(ca_private_key, self.hash_algorithm)
        
        return certificate, private_key
    
    def sign_certificate_signing_request(
        self,
        csr_request: CSRSigningRequest,
        ca: CertificateAuthority,
        ca_private_key: PrivateKeyTypes,
        ca_certificate: x509.Certificate
    ) -> x509.Certificate:
        """
        Sign a Certificate Signing Request
        
        Args:
            csr_request: CSR signing request
            ca: Issuing CA
            ca_private_key: CA's private key
            ca_certificate: CA's certificate
            
        Returns:
            Signed certificate
        """
        # Parse the CSR
        csr = x509.load_pem_x509_csr(csr_request.csr_pem.encode('utf-8'))
        
        # Verify CSR signature
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        
        # Get subject and public key from CSR
        subject = csr.subject
        public_key = csr.public_key()
        
        # Get issuer from CA certificate
        issuer = ca_certificate.subject
        
        # Generate serial number
        serial_number = x509.random_serial_number()
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.utcnow() + timedelta(days=csr_request.validity_days)
        )
        
        # Copy extensions from CSR (if any)
        for extension in csr.extensions:
            # Skip extensions that should be set by the CA
            if extension.oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
                continue
            if extension.oid == x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                continue
            
            builder = builder.add_extension(extension.value, extension.critical)
        
        # Add CA-controlled extensions
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False
        )
        
        # Sign the certificate
        certificate = builder.sign(ca_private_key, self.hash_algorithm)
        
        return certificate
    
    async def create_ca_with_kms_key(
        self,
        ca: CertificateAuthority,
        issuer_ca: Optional[CertificateAuthority] = None
    ) -> Tuple[x509.Certificate, str]:
        """
        Create a CA certificate with KMS-managed key
        
        Args:
            ca: CA database object
            issuer_ca: Issuer CA (None for self-signed root)
            
        Returns:
            Tuple of (certificate, key_identifier)
        """
        try:
            # Create KMS key
            key_identifier, private_key = await self.kms_service.create_ca_key(
                key_type=ca.key_type,
                storage_type=ca.key_storage,
                description=f"PKI-CA-ADMIN CA Key: {ca.name}"
            )
            
            # Get public key
            public_key = await self.kms_service.get_public_key(key_identifier, private_key)
            
            # Build certificate
            subject = self.parse_subject_dn(ca.subject_dn)
            
            # For self-signed root CAs, subject == issuer
            if issuer_ca is None:
                issuer = subject
                issuer_key_id = key_identifier
                issuer_private_key = private_key
            else:
                issuer = self.parse_subject_dn(issuer_ca.subject_dn)
                issuer_key_id = issuer_ca.kms_key_id
                issuer_private_key = None  # Will be loaded from KMS
            
            # Generate serial number
            serial_number = x509.random_serial_number()
            
            # Build certificate
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(issuer)
            builder = builder.public_key(public_key)
            builder = builder.serial_number(serial_number)
            builder = builder.not_valid_before(ca.not_before or datetime.utcnow())
            builder = builder.not_valid_after(ca.not_after or datetime.utcnow() + timedelta(days=3650))
            
            # Add CA extensions
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=ca.max_path_length),
                critical=True
            )
            
            # Key usage for CAs
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Subject Key Identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            
            # Authority Key Identifier (for intermediate CAs)
            if issuer_ca is not None:
                issuer_public_key = await self.kms_service.get_public_key(issuer_key_id, issuer_private_key)
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
                    critical=False
                )
            
            # CRL Distribution Points (if configured)
            if ca.crl_distribution_points:
                distribution_points = []
                for url in ca.crl_distribution_points:
                    distribution_points.append(
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(url)],
                            relative_name=None,
                            crl_issuer=None,
                            reasons=None
                        )
                    )
                builder = builder.add_extension(
                    x509.CRLDistributionPoints(distribution_points),
                    critical=False
                )
            
            # OCSP Responder (if configured)
            if ca.ocsp_responder_url:
                builder = builder.add_extension(
                    x509.AuthorityInformationAccess([
                        x509.AccessDescription(
                            x509.AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(ca.ocsp_responder_url)
                        )
                    ]),
                    critical=False
                )
            
            # Get certificate data to sign
            cert_data_to_sign = builder.tbs_certificate_bytes
            
            # Sign with KMS or local key
            if issuer_ca is None:
                # Self-signed root
                signature = await self.kms_service.sign_certificate_data(
                    key_identifier, cert_data_to_sign, ca.key_type, private_key
                )
            else:
                # Signed by parent CA
                signature = await self.kms_service.sign_certificate_data(
                    issuer_key_id, cert_data_to_sign, issuer_ca.key_type, issuer_private_key
                )
            
            # This is a simplified approach - in production you'd need to properly
            # construct the certificate with the KMS signature
            # For now, fall back to local signing for development
            if ca.key_storage == "file" and private_key:
                if issuer_ca is None or issuer_private_key:
                    signing_key = issuer_private_key if issuer_ca else private_key
                    certificate = builder.sign(signing_key, self.hash_algorithm)
                else:
                    raise ValueError("Cannot sign with KMS-stored issuer key yet")
            else:
                raise ValueError("KMS certificate signing not fully implemented")
            
            return certificate, key_identifier
            
        except Exception as e:
            raise ValueError(f"Failed to create CA with KMS key: {str(e)}")
    
    def certificate_to_pem(self, certificate: x509.Certificate) -> str:
        """
        Convert certificate to PEM format
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            PEM-encoded certificate string
        """
        return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    def private_key_to_pem(
        self, 
        private_key: PrivateKeyTypes, 
        password: Optional[bytes] = None
    ) -> str:
        """
        Convert private key to PEM format
        
        Args:
            private_key: Private key
            password: Optional password for encryption
            
        Returns:
            PEM-encoded private key string
        """
        encryption_algorithm = serialization.NoEncryption()
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')
    
    def get_certificate_fingerprint(self, certificate: x509.Certificate) -> str:
        """
        Get SHA-256 fingerprint of certificate
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            Hex-encoded fingerprint
        """
        return certificate.fingerprint(self.hash_algorithm).hex()
    
    def verify_certificate_chain(
        self, 
        leaf_cert: x509.Certificate, 
        intermediate_certs: list[x509.Certificate],
        root_cert: x509.Certificate
    ) -> bool:
        """
        Verify certificate chain
        
        Args:
            leaf_cert: End-entity certificate
            intermediate_certs: List of intermediate certificates
            root_cert: Root certificate
            
        Returns:
            True if chain is valid
        """
        try:
            # This is a simplified verification - in production you'd want
            # to use a proper certificate path validation library like pyOpenSSL
            
            # Check each certificate in the chain
            cert_to_verify = leaf_cert
            issuer_cert = intermediate_certs[0] if intermediate_certs else root_cert
            
            # Verify leaf certificate against its issuer
            try:
                issuer_cert.public_key().verify(
                    cert_to_verify.signature,
                    cert_to_verify.tbs_certificate_bytes,
                    cert_to_verify.signature_hash_algorithm
                )
            except Exception:
                return False
            
            # Verify intermediate certificates against their issuers
            for i, intermediate_cert in enumerate(intermediate_certs):
                # Determine the issuer certificate
                if i + 1 < len(intermediate_certs):
                    issuer_cert = intermediate_certs[i + 1]
                else:
                    issuer_cert = root_cert
                
                # Verify signature
                try:
                    issuer_cert.public_key().verify(
                        intermediate_cert.signature,
                        intermediate_cert.tbs_certificate_bytes,
                        intermediate_cert.signature_hash_algorithm
                    )
                except Exception:
                    return False
            
            return True
            
        except Exception:
            return False


# Global instance
crypto_service = CryptographicService()


def get_crypto_service() -> CryptographicService:
    """Get the global cryptographic service instance"""
    return crypto_service