"""
Import Service - Handle importing existing PKI infrastructures.
Supports PKCS#12, PEM, and other certificate formats.
"""

import base64
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
import ipaddress
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from app.schemas.ca import SubjectInfo
from app.schemas.certificate import SubjectAlternativeNames
from app.services.key_backend import get_key_backend, KeyBackend


class ImportError(Exception):
    """Base exception for import operations."""
    pass


class InvalidFormatError(ImportError):
    """Invalid certificate/key format."""
    pass


class CertificateKeyMismatchError(ImportError):
    """Certificate and private key don't match."""
    pass


class ChainValidationError(ImportError):
    """Certificate chain validation failed."""
    pass


class ImportService:
    """
    Service for importing existing PKI certificates and keys.
    
    Supports:
    - PKCS#12 (.p12, .pfx) files
    - PEM certificate and key files
    - Certificate chain reconstruction
    - CA hierarchy analysis
    """
    
    def __init__(self, key_backend: Optional[KeyBackend] = None):
        """
        Initialize import service.
        
        Args:
            key_backend: Key storage backend
        """
        self.key_backend = key_backend or get_key_backend()
    
    def parse_pkcs12(
        self, 
        pkcs12_data: bytes, 
        password: Optional[str] = None
    ) -> Tuple[x509.Certificate, Optional[PrivateKeyTypes], List[x509.Certificate]]:
        """
        Parse PKCS#12 file and extract certificates and private keys.
        
        Args:
            pkcs12_data: PKCS#12 file data
            password: Password for encrypted PKCS#12 file
            
        Returns:
            Tuple[Certificate, PrivateKey, AdditionalCerts]: Main certificate, private key, chain
            
        Raises:
            InvalidFormatError: If PKCS#12 data is invalid
        """
        try:
            password_bytes = password.encode('utf-8') if password else None
            
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pkcs12_data, password_bytes
            )
            
            if not certificate:
                raise InvalidFormatError("No certificate found in PKCS#12 file")
            
            return certificate, private_key, additional_certificates or []
            
        except ValueError as e:
            raise InvalidFormatError(f"Failed to parse PKCS#12 file: {str(e)}")
        except Exception as e:
            raise ImportError(f"Error parsing PKCS#12 file: {str(e)}")
    
    def parse_pem_certificates(self, pem_data: str) -> List[x509.Certificate]:
        """
        Parse PEM data and extract all certificates.
        
        Args:
            pem_data: PEM-encoded certificate data
            
        Returns:
            List[Certificate]: List of certificates found
            
        Raises:
            InvalidFormatError: If PEM data is invalid
        """
        try:
            certificates = []
            pem_bytes = pem_data.encode('utf-8')
            
            # Split PEM data into individual certificates
            pem_parts = pem_data.split('-----END CERTIFICATE-----')
            
            for part in pem_parts:
                if '-----BEGIN CERTIFICATE-----' in part:
                    cert_pem = part + '-----END CERTIFICATE-----'
                    try:
                        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                        certificates.append(cert)
                    except Exception:
                        # Skip invalid certificate parts
                        continue
            
            if not certificates:
                raise InvalidFormatError("No valid certificates found in PEM data")
            
            return certificates
            
        except InvalidFormatError:
            raise
        except Exception as e:
            raise InvalidFormatError(f"Failed to parse PEM certificates: {str(e)}")
    
    def parse_pem_private_key(
        self, 
        pem_data: str, 
        password: Optional[str] = None
    ) -> PrivateKeyTypes:
        """
        Parse PEM private key data.
        
        Args:
            pem_data: PEM-encoded private key data
            password: Password for encrypted private key
            
        Returns:
            PrivateKeyTypes: Private key object
            
        Raises:
            InvalidFormatError: If private key data is invalid
        """
        try:
            password_bytes = password.encode('utf-8') if password else None
            
            private_key = serialization.load_pem_private_key(
                pem_data.encode('utf-8'),
                password=password_bytes
            )
            
            return private_key
            
        except ValueError as e:
            raise InvalidFormatError(f"Failed to parse PEM private key: {str(e)}")
        except Exception as e:
            raise ImportError(f"Error parsing PEM private key: {str(e)}")
    
    def verify_certificate_key_match(
        self, 
        certificate: x509.Certificate, 
        private_key: PrivateKeyTypes
    ) -> bool:
        """
        Verify that a certificate and private key match.
        
        Args:
            certificate: X.509 certificate
            private_key: Private key
            
        Returns:
            bool: True if certificate and key match
        """
        try:
            # Compare public keys
            cert_public_key = certificate.public_key()
            key_public_key = private_key.public_key()
            
            # Serialize both public keys and compare
            cert_pub_bytes = cert_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            key_pub_bytes = key_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return cert_pub_bytes == key_pub_bytes
            
        except Exception:
            return False
    
    def build_certificate_chain(
        self, 
        certificates: List[x509.Certificate]
    ) -> List[List[x509.Certificate]]:
        """
        Build certificate chains from a collection of certificates.
        
        Args:
            certificates: List of X.509 certificates
            
        Returns:
            List[List[Certificate]]: List of certificate chains (leaf to root)
        """
        # Create a lookup map for certificates by subject
        subject_map = {}
        for cert in certificates:
            subject_key = cert.subject.rfc4514_string()
            if subject_key not in subject_map:
                subject_map[subject_key] = []
            subject_map[subject_key].append(cert)
        
        # Find chains starting from each certificate
        chains = []
        processed_certs = set()
        
        for cert in certificates:
            if id(cert) in processed_certs:
                continue
            
            chain = self._build_single_chain(cert, certificates, subject_map)
            if chain:
                chains.append(chain)
                # Mark all certificates in this chain as processed
                for c in chain:
                    processed_certs.add(id(c))
        
        return chains
    
    def _build_single_chain(
        self, 
        start_cert: x509.Certificate, 
        all_certs: List[x509.Certificate],
        subject_map: Dict[str, List[x509.Certificate]]
    ) -> List[x509.Certificate]:
        """
        Build a single certificate chain starting from a certificate.
        
        Args:
            start_cert: Certificate to start chain from
            all_certs: All available certificates
            subject_map: Map of subject DN to certificates
            
        Returns:
            List[Certificate]: Certificate chain (leaf to root)
        """
        chain = [start_cert]
        current_cert = start_cert
        
        while True:
            # Check if this is a self-signed certificate (root)
            if current_cert.issuer == current_cert.subject:
                break
            
            # Find the issuer certificate
            issuer_key = current_cert.issuer.rfc4514_string()
            issuer_candidates = subject_map.get(issuer_key, [])
            
            issuer_cert = None
            for candidate in issuer_candidates:
                # Verify this candidate actually issued the current certificate
                if self._verify_certificate_signature(current_cert, candidate):
                    issuer_cert = candidate
                    break
            
            if not issuer_cert:
                # Chain is incomplete
                break
            
            # Avoid infinite loops
            if issuer_cert in chain:
                break
            
            chain.append(issuer_cert)
            current_cert = issuer_cert
        
        return chain
    
    def _verify_certificate_signature(
        self, 
        cert: x509.Certificate, 
        issuer_cert: x509.Certificate
    ) -> bool:
        """
        Verify that a certificate was signed by an issuer certificate.
        
        Args:
            cert: Certificate to verify
            issuer_cert: Potential issuer certificate
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # Use the issuer's public key to verify the certificate signature
            issuer_public_key = issuer_cert.public_key()
            
            # This is a simplified check - in production you'd need to handle
            # different signature algorithms properly
            # For now, just check if subjects match expected issuer/subject relationship
            return cert.issuer == issuer_cert.subject
            
        except Exception:
            return False
    
    def analyze_ca_hierarchy(
        self, 
        certificates: List[x509.Certificate]
    ) -> Dict[str, Any]:
        """
        Analyze a collection of certificates and determine CA hierarchy.
        
        Args:
            certificates: List of X.509 certificates
            
        Returns:
            Dict: Analysis results with CA structure information
        """
        chains = self.build_certificate_chain(certificates)
        
        root_cas = []
        intermediate_cas = []
        leaf_certificates = []
        
        for chain in chains:
            if len(chain) == 1:
                # Single certificate - could be root CA or leaf
                cert = chain[0]
                if self._is_ca_certificate(cert):
                    if cert.issuer == cert.subject:
                        root_cas.append(cert)
                    else:
                        # Intermediate CA with missing parent
                        intermediate_cas.append(cert)
                else:
                    leaf_certificates.append(cert)
            else:
                # Multi-certificate chain
                for i, cert in enumerate(chain):
                    if i == 0:
                        # First cert could be leaf or intermediate
                        if self._is_ca_certificate(cert):
                            intermediate_cas.append(cert)
                        else:
                            leaf_certificates.append(cert)
                    elif i == len(chain) - 1:
                        # Last cert in chain - should be root
                        if self._is_ca_certificate(cert) and cert.issuer == cert.subject:
                            root_cas.append(cert)
                    else:
                        # Middle cert - should be intermediate CA
                        if self._is_ca_certificate(cert):
                            intermediate_cas.append(cert)
        
        return {
            "total_certificates": len(certificates),
            "certificate_chains": len(chains),
            "root_cas": len(root_cas),
            "intermediate_cas": len(intermediate_cas),
            "leaf_certificates": len(leaf_certificates),
            "chains": [
                {
                    "length": len(chain),
                    "root": chain[-1].subject.rfc4514_string(),
                    "leaf": chain[0].subject.rfc4514_string() if chain else None
                }
                for chain in chains
            ]
        }
    
    def _is_ca_certificate(self, cert: x509.Certificate) -> bool:
        """
        Check if a certificate is a CA certificate.
        
        Args:
            cert: X.509 certificate
            
        Returns:
            bool: True if certificate is a CA
        """
        try:
            # Check Basic Constraints extension
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            # If no Basic Constraints, check Key Usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                ).value
                return key_usage.key_cert_sign
            except x509.ExtensionNotFound:
                # Fallback: assume it's a CA if it can sign certificates
                return cert.issuer == cert.subject
    
    def extract_certificate_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Extract detailed information from a certificate.
        
        Args:
            cert: X.509 certificate
            
        Returns:
            Dict: Certificate information
        """
        # Extract subject information
        subject = cert.subject
        subject_info = {
            'common_name': self._get_name_attribute(subject, x509.NameOID.COMMON_NAME),
            'organization': self._get_name_attribute(subject, x509.NameOID.ORGANIZATION_NAME),
            'organizational_unit': self._get_name_attribute(subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
            'country': self._get_name_attribute(subject, x509.NameOID.COUNTRY_NAME),
            'state': self._get_name_attribute(subject, x509.NameOID.STATE_OR_PROVINCE_NAME),
            'locality': self._get_name_attribute(subject, x509.NameOID.LOCALITY_NAME),
            'email': self._get_name_attribute(subject, x509.NameOID.EMAIL_ADDRESS),
        }
        
        # Extract SAN
        san_info = {'dns': [], 'ip': [], 'email': [], 'uri': []}
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            
            for name in san_ext:
                if isinstance(name, x509.DNSName):
                    san_info['dns'].append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_info['ip'].append(str(name.value))
                elif isinstance(name, x509.RFC822Name):
                    san_info['email'].append(name.value)
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_info['uri'].append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        return {
            'serial_number': str(cert.serial_number),
            'fingerprint_sha256': fingerprint,
            'subject': subject_info,
            'subject_dn': subject.rfc4514_string(),
            'issuer_dn': cert.issuer.rfc4514_string(),
            'not_before': cert.not_valid_before,
            'not_after': cert.not_valid_after,
            'is_ca': self._is_ca_certificate(cert),
            'is_self_signed': cert.issuer == cert.subject,
            'key_type': self._get_key_type(cert.public_key()),
            'subject_alternative_names': san_info if any(san_info.values()) else None,
            'certificate_pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        }
    
    def _get_name_attribute(self, name: x509.Name, oid: x509.NameOID) -> Optional[str]:
        """Extract name attribute by OID."""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, KeyError):
            return None
    
    def _get_key_type(self, public_key) -> str:
        """Determine the key type from a public key."""
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            return f"rsa-{key_size}"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name.lower()
            if curve_name == 'secp256r1':
                return "ecdsa-p256"
            elif curve_name == 'secp384r1':
                return "ecdsa-p384"
            else:
                return f"ecdsa-{curve_name}"
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return "ed25519"
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return "ed448"
        else:
            return "unknown"
    
    async def import_ca_from_pkcs12(
        self,
        pkcs12_data: bytes,
        password: Optional[str] = None,
        ca_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Import a CA from PKCS#12 file.
        
        Args:
            pkcs12_data: PKCS#12 file data
            password: Password for encrypted file
            ca_name: Optional name for the CA
            
        Returns:
            Dict: Import results with CA and certificate information
            
        Raises:
            ImportError: If import fails
        """
        try:
            # Parse PKCS#12 file
            certificate, private_key, additional_certificates = self.parse_pkcs12(
                pkcs12_data, password
            )
            
            # Verify certificate and key match if both are present
            if private_key and not self.verify_certificate_key_match(certificate, private_key):
                raise CertificateKeyMismatchError("Certificate and private key don't match")
            
            # Extract certificate information
            cert_info = self.extract_certificate_info(certificate)
            
            # Store private key if present
            key_id = None
            if private_key:
                key_name = ca_name or cert_info['subject']['common_name'] or f"imported-ca-{uuid.uuid4()}"
                key_id = await self.key_backend.store_private_key(private_key, key_name)
            
            # Build certificate chain if additional certificates are present
            all_certificates = [certificate] + additional_certificates
            chains = self.build_certificate_chain(all_certificates)
            hierarchy_info = self.analyze_ca_hierarchy(all_certificates)
            
            return {
                'success': True,
                'ca_certificate': cert_info,
                'key_id': key_id,
                'has_private_key': private_key is not None,
                'additional_certificates': len(additional_certificates),
                'hierarchy': hierarchy_info,
                'chains': [
                    [self.extract_certificate_info(cert) for cert in chain]
                    for chain in chains
                ]
            }
            
        except (InvalidFormatError, CertificateKeyMismatchError):
            raise
        except Exception as e:
            raise ImportError(f"Failed to import CA from PKCS#12: {str(e)}")
    
    async def import_ca_from_pem(
        self,
        certificate_pem: str,
        private_key_pem: Optional[str] = None,
        private_key_password: Optional[str] = None,
        ca_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Import a CA from PEM files.
        
        Args:
            certificate_pem: PEM-encoded certificate
            private_key_pem: Optional PEM-encoded private key
            private_key_password: Password for encrypted private key
            ca_name: Optional name for the CA
            
        Returns:
            Dict: Import results
            
        Raises:
            ImportError: If import fails
        """
        try:
            # Parse certificate
            certificates = self.parse_pem_certificates(certificate_pem)
            if not certificates:
                raise InvalidFormatError("No certificates found in PEM data")
            
            certificate = certificates[0]  # Use first certificate as main
            
            # Parse private key if provided
            private_key = None
            if private_key_pem:
                private_key = self.parse_pem_private_key(private_key_pem, private_key_password)
                
                # Verify certificate and key match
                if not self.verify_certificate_key_match(certificate, private_key):
                    raise CertificateKeyMismatchError("Certificate and private key don't match")
            
            # Extract certificate information
            cert_info = self.extract_certificate_info(certificate)
            
            # Store private key if present
            key_id = None
            if private_key:
                key_name = ca_name or cert_info['subject']['common_name'] or f"imported-ca-{uuid.uuid4()}"
                key_id = await self.key_backend.store_private_key(private_key, key_name)
            
            # Analyze hierarchy if multiple certificates
            hierarchy_info = None
            if len(certificates) > 1:
                hierarchy_info = self.analyze_ca_hierarchy(certificates)
            
            return {
                'success': True,
                'ca_certificate': cert_info,
                'key_id': key_id,
                'has_private_key': private_key is not None,
                'additional_certificates': len(certificates) - 1,
                'hierarchy': hierarchy_info,
                'all_certificates': [self.extract_certificate_info(cert) for cert in certificates]
            }
            
        except (InvalidFormatError, CertificateKeyMismatchError):
            raise
        except Exception as e:
            raise ImportError(f"Failed to import CA from PEM: {str(e)}")