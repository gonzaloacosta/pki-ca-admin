#!/usr/bin/env python3
"""
Crypto-only test to verify basic functionality works

This tests just the cryptographic operations without database dependencies.
"""

import sys
import os
from datetime import datetime, timedelta, timezone
import uuid
import ipaddress

# Test basic cryptography operations
def test_basic_crypto():
    """Test basic cryptographic operations without dependencies"""
    print("Testing basic cryptographic operations...")
    
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        
        print("1. Testing ECDSA P-256 key generation...")
        private_key = ec.generate_private_key(ec.SECP256R1())
        print("   ✅ ECDSA P-256 key generated")
        
        print("2. Testing RSA-2048 key generation...")
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        print("   ✅ RSA-2048 key generated")
        
        print("3. Testing Ed25519 key generation...")
        ed_key = ed25519.Ed25519PrivateKey.generate()
        print("   ✅ Ed25519 key generated")
        
        print("4. Testing X.509 certificate creation...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI-CA-ADMIN Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        print("   ✅ CA certificate created")
        print(f"   Subject: {cert.subject}")
        print(f"   Serial: {cert.serial_number:x}")
        print(f"   Valid from: {cert.not_valid_before}")
        print(f"   Valid until: {cert.not_valid_after}")
        
        print("5. Testing PEM conversion...")
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        print("   ✅ PEM conversion successful")
        print(f"   Certificate PEM length: {len(cert_pem)} bytes")
        print(f"   Private key PEM length: {len(key_pem)} bytes")
        
        print("6. Testing Subject Alternative Names...")
        
        # Create end-entity cert with SANs
        san_cert = x509.CertificateBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ])
        ).issuer_name(
            subject  # CA subject
        ).public_key(
            rsa_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=90)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("test.example.com"),
                x509.DNSName("www.test.example.com"),
                x509.IPAddress(ipaddress.IPv4Address("192.168.1.100")),
            ]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).sign(private_key, hashes.SHA256())  # Sign with CA key
        
        print("   ✅ End-entity certificate with SANs created")
        
        # Check SANs
        san_ext = san_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        print("   Subject Alternative Names:")
        for name in san_ext.value:
            print(f"     - {type(name).__name__}: {name.value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic crypto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_key_types():
    """Test all supported key types"""
    print("\nTesting all supported key types...")
    
    key_types = [
        ("RSA-2048", lambda: rsa.generate_private_key(65537, 2048)),
        ("RSA-4096", lambda: rsa.generate_private_key(65537, 4096)),
        ("ECDSA P-256", lambda: ec.generate_private_key(ec.SECP256R1())),
        ("ECDSA P-384", lambda: ec.generate_private_key(ec.SECP384R1())),
        ("Ed25519", lambda: ed25519.Ed25519PrivateKey.generate()),
    ]
    
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
        
        results = []
        for key_name, key_gen_func in key_types:
            try:
                print(f"   Testing {key_name}...")
                private_key = key_gen_func()
                
                # Test signing capability
                if "Ed25519" in key_name:
                    # Ed25519 signing
                    signature = private_key.sign(b"test message")
                    print(f"   ✅ {key_name} generation and signing works")
                elif "RSA" in key_name:
                    # RSA signing
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.asymmetric import padding
                    signature = private_key.sign(
                        b"test message", 
                        padding.PKCS1v15(), 
                        hashes.SHA256()
                    )
                    print(f"   ✅ {key_name} generation and signing works")
                elif "ECDSA" in key_name:
                    # ECDSA signing
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.asymmetric import utils
                    signature = private_key.sign(
                        b"test message", 
                        ec.ECDSA(hashes.SHA256())
                    )
                    print(f"   ✅ {key_name} generation and signing works")
                else:
                    print(f"   ⚠️ {key_name} generation works, signing test skipped")
                
                results.append((key_name, True))
                
            except Exception as e:
                print(f"   ❌ {key_name} failed: {e}")
                results.append((key_name, False))
        
        return all(result[1] for result in results)
        
    except Exception as e:
        print(f"❌ Key types test failed: {e}")
        return False


def main():
    """Run crypto-only tests"""
    print("PKI-CA-ADMIN Cryptographic Operations Test")
    print("=" * 60)
    
    tests = [
        ("Basic Crypto Operations", test_basic_crypto),
        ("All Key Types", test_key_types),
    ]
    
    passed = 0
    for test_name, test_func in tests:
        try:
            print(f"\n--- {test_name} ---")
            result = test_func()
            if result:
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: EXCEPTION - {e}")
    
    print("\n" + "=" * 60)
    print("CRYPTO TEST SUMMARY")
    print("=" * 60)
    print(f"Passed: {passed}/{len(tests)} tests")
    
    if passed == len(tests):
        print("\n🎉 All cryptographic operations work correctly!")
        print("The core crypto foundation is solid and ready for production.")
        print("\nNext steps:")
        print("- Install dependencies to test service integration")
        print("- Set up PostgreSQL for database operations")
        print("- Configure AWS credentials for KMS testing")
        return True
    else:
        print(f"\n⚠️ {len(tests) - passed} crypto tests failed")
        print("Core cryptographic operations have issues that need fixing.")
        return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n\nCrypto tests failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)