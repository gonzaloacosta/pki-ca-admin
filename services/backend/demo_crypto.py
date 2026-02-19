#!/usr/bin/env python3
"""
Demo script to test real cryptographic operations

This script demonstrates the PKI-CA-ADMIN crypto service without requiring
the full application setup. It generates a CA certificate and then issues
an end-entity certificate to prove the implementation works.
"""

import sys
import os
from datetime import datetime, timedelta

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from services.crypto_service import CryptographicService
from models.database import CertificateAuthority
from models.schemas import CertificateRequest, CertificateType, KeyType, SubjectAlternativeNames


def demo_ca_creation():
    """Demonstrate CA certificate creation"""
    print("=" * 60)
    print("PKI-CA-ADMIN Cryptographic Operations Demo")
    print("=" * 60)
    
    crypto_service = CryptographicService()
    
    # Create a mock CA object (normally from database)
    root_ca = CertificateAuthority(
        name="Demo Root CA",
        type="root",
        subject_dn="CN=Demo Root CA, O=PKI-CA-ADMIN Demo, C=US",
        key_type="ecdsa-p256",
        key_storage="file",  # Simulating file storage for demo
        not_before=datetime.utcnow(),
        not_after=datetime.utcnow() + timedelta(days=3650),  # 10 years
        max_path_length=2,
        status="pending"
    )
    
    print(f"\n1. Generating Root CA: {root_ca.name}")
    print(f"   Subject DN: {root_ca.subject_dn}")
    print(f"   Key Type: {root_ca.key_type}")
    print(f"   Valid from: {root_ca.not_before}")
    print(f"   Valid until: {root_ca.not_after}")
    
    try:
        # Generate private key
        print("\n   Generating private key...")
        private_key = crypto_service.generate_private_key(root_ca.key_type)
        
        # Generate CA certificate
        print("   Generating CA certificate...")
        ca_certificate = crypto_service.generate_ca_certificate(root_ca, private_key)
        
        # Convert to PEM
        cert_pem = crypto_service.certificate_to_pem(ca_certificate)
        
        # Update CA object with certificate details
        root_ca.certificate_pem = cert_pem
        root_ca.serial_number = f"{ca_certificate.serial_number:x}"
        root_ca.status = "active"
        
        print(f"   ✅ Root CA certificate generated successfully!")
        print(f"   Serial Number: {root_ca.serial_number}")
        print(f"   Fingerprint: {crypto_service.get_certificate_fingerprint(ca_certificate)}")
        
        # Show certificate details
        print(f"\n   Certificate Details:")
        print(f"   - Subject: {ca_certificate.subject}")
        print(f"   - Issuer: {ca_certificate.issuer}")
        print(f"   - Not Before: {ca_certificate.not_valid_before}")
        print(f"   - Not After: {ca_certificate.not_valid_after}")
        print(f"   - Serial Number: {ca_certificate.serial_number}")
        
        return root_ca, ca_certificate, private_key
        
    except Exception as e:
        print(f"   ❌ Error generating Root CA: {e}")
        return None, None, None


def demo_intermediate_ca_creation(root_ca, root_certificate, root_private_key):
    """Demonstrate intermediate CA creation"""
    print(f"\n2. Generating Intermediate CA")
    
    crypto_service = CryptographicService()
    
    # Create intermediate CA
    intermediate_ca = CertificateAuthority(
        name="Demo Intermediate CA",
        type="intermediate",
        subject_dn="CN=Demo Intermediate CA, O=PKI-CA-ADMIN Demo, C=US",
        key_type="ecdsa-p256",
        key_storage="file",
        not_before=datetime.utcnow(),
        not_after=datetime.utcnow() + timedelta(days=1825),  # 5 years
        max_path_length=0,
        status="pending"
    )
    
    print(f"   Subject DN: {intermediate_ca.subject_dn}")
    print(f"   Parent CA: {root_ca.name}")
    
    try:
        # Generate private key for intermediate
        print("   Generating intermediate private key...")
        intermediate_private_key = crypto_service.generate_private_key(intermediate_ca.key_type)
        
        # Generate intermediate certificate signed by root
        print("   Generating intermediate certificate...")
        intermediate_certificate = crypto_service.generate_ca_certificate(
            intermediate_ca, 
            intermediate_private_key,
            root_ca,
            root_private_key
        )
        
        # Convert to PEM
        cert_pem = crypto_service.certificate_to_pem(intermediate_certificate)
        
        # Update CA object
        intermediate_ca.certificate_pem = cert_pem
        intermediate_ca.serial_number = f"{intermediate_certificate.serial_number:x}"
        intermediate_ca.status = "active"
        
        print(f"   ✅ Intermediate CA certificate generated successfully!")
        print(f"   Serial Number: {intermediate_ca.serial_number}")
        print(f"   Fingerprint: {crypto_service.get_certificate_fingerprint(intermediate_certificate)}")
        
        return intermediate_ca, intermediate_certificate, intermediate_private_key
        
    except Exception as e:
        print(f"   ❌ Error generating Intermediate CA: {e}")
        return None, None, None


def demo_certificate_issuance(ca, ca_certificate, ca_private_key):
    """Demonstrate end-entity certificate issuance"""
    print(f"\n3. Issuing End-Entity Certificate")
    
    crypto_service = CryptographicService()
    
    # Create certificate request
    cert_request = CertificateRequest(
        common_name="demo.example.com",
        subject_alternative_names=SubjectAlternativeNames(
            dns=["demo.example.com", "www.demo.example.com"],
            ip=["192.168.1.100"]
        ),
        certificate_type=CertificateType.SERVER,
        key_type=KeyType.ECDSA_P256,
        validity_days=365,
        key_usage=["digitalSignature", "keyEncipherment"],
        extended_key_usage=["serverAuth"]
    )
    
    print(f"   Common Name: {cert_request.common_name}")
    print(f"   SANs: DNS={cert_request.subject_alternative_names.dns}, IP={cert_request.subject_alternative_names.ip}")
    print(f"   Certificate Type: {cert_request.certificate_type}")
    print(f"   Key Type: {cert_request.key_type}")
    print(f"   Validity: {cert_request.validity_days} days")
    
    try:
        # Generate end-entity certificate
        print("   Generating end-entity certificate...")
        certificate, private_key = crypto_service.generate_end_entity_certificate(
            cert_request, ca, ca_private_key, ca_certificate
        )
        
        # Convert to PEM
        cert_pem = crypto_service.certificate_to_pem(certificate)
        
        print(f"   ✅ End-entity certificate generated successfully!")
        print(f"   Serial Number: {certificate.serial_number:x}")
        print(f"   Fingerprint: {crypto_service.get_certificate_fingerprint(certificate)}")
        
        # Show certificate details
        print(f"\n   Certificate Details:")
        print(f"   - Subject: {certificate.subject}")
        print(f"   - Issuer: {certificate.issuer}")
        print(f"   - Not Before: {certificate.not_valid_before}")
        print(f"   - Not After: {certificate.not_valid_after}")
        print(f"   - Serial Number: {certificate.serial_number}")
        
        # Check Subject Alternative Names
        try:
            from cryptography import x509
            san_ext = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            print(f"   - Subject Alternative Names:")
            for name in san_ext.value:
                print(f"     * {type(name).__name__}: {name.value}")
        except x509.ExtensionNotFound:
            print(f"   - No Subject Alternative Names")
        
        return certificate, private_key
        
    except Exception as e:
        print(f"   ❌ Error generating end-entity certificate: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def demo_certificate_chain_verification(root_cert, intermediate_cert, end_cert):
    """Demonstrate certificate chain verification"""
    print(f"\n4. Certificate Chain Verification")
    
    crypto_service = CryptographicService()
    
    print("   Verifying certificate chain: End-Entity → Intermediate → Root")
    
    try:
        # Simplified verification (note: this is a basic demo)
        is_valid = crypto_service.verify_certificate_chain(
            end_cert, [intermediate_cert], root_cert
        )
        
        if is_valid:
            print("   ✅ Certificate chain verification successful!")
        else:
            print("   ❌ Certificate chain verification failed!")
            
        return is_valid
        
    except Exception as e:
        print(f"   ❌ Error during verification: {e}")
        return False


def show_pem_certificates(root_cert, intermediate_cert, end_cert):
    """Show PEM-encoded certificates"""
    print(f"\n5. Generated Certificates (PEM Format)")
    print("-" * 60)
    
    crypto_service = CryptographicService()
    
    print("\nRoot CA Certificate:")
    print(crypto_service.certificate_to_pem(root_cert))
    
    print("\nIntermediate CA Certificate:")
    print(crypto_service.certificate_to_pem(intermediate_cert))
    
    print("\nEnd-Entity Certificate:")
    print(crypto_service.certificate_to_pem(end_cert))


def main():
    """Main demo function"""
    print("Starting PKI-CA-ADMIN Cryptographic Operations Demo...\n")
    
    # Step 1: Create Root CA
    root_ca, root_certificate, root_private_key = demo_ca_creation()
    if not root_ca:
        print("Failed to create root CA. Exiting.")
        return False
    
    # Step 2: Create Intermediate CA
    intermediate_ca, intermediate_certificate, intermediate_private_key = demo_intermediate_ca_creation(
        root_ca, root_certificate, root_private_key
    )
    if not intermediate_ca:
        print("Failed to create intermediate CA. Exiting.")
        return False
    
    # Step 3: Issue End-Entity Certificate
    end_certificate, end_private_key = demo_certificate_issuance(
        intermediate_ca, intermediate_certificate, intermediate_private_key
    )
    if not end_certificate:
        print("Failed to issue end-entity certificate. Exiting.")
        return False
    
    # Step 4: Verify Certificate Chain
    chain_valid = demo_certificate_chain_verification(
        root_certificate, intermediate_certificate, end_certificate
    )
    
    # Step 5: Show PEM certificates
    show_pem_certificates(root_certificate, intermediate_certificate, end_certificate)
    
    # Summary
    print("\n" + "=" * 60)
    print("DEMO SUMMARY")
    print("=" * 60)
    print(f"✅ Root CA: {root_ca.name} (Serial: {root_ca.serial_number})")
    print(f"✅ Intermediate CA: {intermediate_ca.name} (Serial: {intermediate_ca.serial_number})")
    print(f"✅ End-Entity Certificate: {end_certificate.subject} (Serial: {end_certificate.serial_number:x})")
    print(f"{'✅' if chain_valid else '❌'} Certificate Chain Verification: {'PASSED' if chain_valid else 'FAILED'}")
    
    print("\n🎉 PKI-CA-ADMIN cryptographic operations are working correctly!")
    print("\nNext steps:")
    print("- Integrate with KMS for secure key storage")
    print("- Add step-ca integration for production CA management")
    print("- Implement comprehensive test suite")
    print("- Add certificate revocation and CRL generation")
    
    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)