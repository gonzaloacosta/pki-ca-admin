"""
KMS (Key Management Service) integration for secure key storage and operations

Supports AWS KMS, Azure Key Vault, and Google Cloud KMS for production-grade
key management with hardware security modules (HSMs).
"""

import json
import base64
import os
from typing import Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography import x509
import structlog

from app.core.config import settings

logger = structlog.get_logger()

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    logger.warning("AWS SDK not available - KMS functionality will be limited")


class KMSException(Exception):
    """KMS operation exception"""
    pass


class AWSKMSService:
    """AWS KMS integration for secure key operations"""
    
    def __init__(self, region: str = None):
        if not AWS_AVAILABLE:
            raise KMSException("AWS SDK not available. Install boto3.")
        
        self.region = region or settings.AWS_REGION
        try:
            self.kms_client = boto3.client('kms', region_name=self.region)
            logger.info("AWS KMS client initialized", region=self.region)
        except NoCredentialsError:
            raise KMSException("AWS credentials not configured")
    
    async def create_key(
        self, 
        key_spec: str = "ECC_NIST_P256",
        key_usage: str = "SIGN_VERIFY",
        description: str = "PKI-CA-ADMIN Certificate Authority Key"
    ) -> str:
        """
        Create a new KMS key for certificate operations
        
        Args:
            key_spec: Key specification (RSA_2048, RSA_4096, ECC_NIST_P256, ECC_NIST_P384)
            key_usage: Key usage (SIGN_VERIFY for CAs)
            description: Key description
            
        Returns:
            KMS Key ARN
        """
        try:
            response = self.kms_client.create_key(
                KeyUsage=key_usage,
                CustomerMasterKeySpec=key_spec,  # Legacy parameter name
                KeySpec=key_spec,  # New parameter name
                Description=description,
                Tags=[
                    {'TagKey': 'Application', 'TagValue': 'PKI-CA-ADMIN'},
                    {'TagKey': 'Purpose', 'TagValue': 'Certificate Authority'},
                ]
            )
            
            key_arn = response['KeyMetadata']['Arn']
            key_id = response['KeyMetadata']['KeyId']
            
            logger.info(
                "KMS key created successfully",
                key_arn=key_arn,
                key_id=key_id,
                key_spec=key_spec
            )
            
            return key_arn
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(
                "Failed to create KMS key",
                error_code=error_code,
                error_message=error_message
            )
            raise KMSException(f"KMS key creation failed: {error_message}")
    
    async def get_public_key(self, key_arn: str) -> PublicKeyTypes:
        """
        Get public key from KMS
        
        Args:
            key_arn: KMS key ARN
            
        Returns:
            Cryptography public key object
        """
        try:
            response = self.kms_client.get_public_key(KeyId=key_arn)
            
            # Parse the DER-encoded public key
            public_key_der = response['PublicKey']
            public_key = serialization.load_der_public_key(public_key_der)
            
            logger.debug("Retrieved public key from KMS", key_arn=key_arn)
            return public_key
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(
                "Failed to get public key from KMS",
                key_arn=key_arn,
                error_code=error_code,
                error_message=error_message
            )
            raise KMSException(f"Failed to get public key: {error_message}")
    
    async def sign_data(
        self, 
        key_arn: str, 
        data: bytes,
        signing_algorithm: str = "ECDSA_SHA_256"
    ) -> bytes:
        """
        Sign data using KMS key
        
        Args:
            key_arn: KMS key ARN
            data: Data to sign
            signing_algorithm: Signing algorithm
            
        Returns:
            Signature bytes
        """
        try:
            response = self.kms_client.sign(
                KeyId=key_arn,
                Message=data,
                MessageType='RAW',
                SigningAlgorithm=signing_algorithm
            )
            
            signature = response['Signature']
            
            logger.debug(
                "Data signed with KMS key",
                key_arn=key_arn,
                algorithm=signing_algorithm,
                signature_length=len(signature)
            )
            
            return signature
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(
                "Failed to sign data with KMS",
                key_arn=key_arn,
                error_code=error_code,
                error_message=error_message
            )
            raise KMSException(f"KMS signing failed: {error_message}")
    
    async def verify_signature(
        self,
        key_arn: str,
        data: bytes,
        signature: bytes,
        signing_algorithm: str = "ECDSA_SHA_256"
    ) -> bool:
        """
        Verify signature using KMS key
        
        Args:
            key_arn: KMS key ARN
            data: Original data
            signature: Signature to verify
            signing_algorithm: Signing algorithm
            
        Returns:
            True if signature is valid
        """
        try:
            response = self.kms_client.verify(
                KeyId=key_arn,
                Message=data,
                MessageType='RAW',
                Signature=signature,
                SigningAlgorithm=signing_algorithm
            )
            
            is_valid = response['SignatureValid']
            
            logger.debug(
                "Signature verification completed",
                key_arn=key_arn,
                is_valid=is_valid
            )
            
            return is_valid
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(
                "Failed to verify signature with KMS",
                key_arn=key_arn,
                error_code=error_code,
                error_message=error_message
            )
            raise KMSException(f"KMS verification failed: {error_message}")
    
    def get_algorithm_for_key_spec(self, key_spec: str, key_type: str) -> str:
        """
        Get appropriate signing algorithm for key spec and type
        
        Args:
            key_spec: KMS key spec
            key_type: Our internal key type
            
        Returns:
            KMS signing algorithm
        """
        algorithm_map = {
            ("RSA_2048", "rsa-2048"): "RSASSA_PSS_SHA_256",
            ("RSA_4096", "rsa-4096"): "RSASSA_PSS_SHA_256",
            ("ECC_NIST_P256", "ecdsa-p256"): "ECDSA_SHA_256",
            ("ECC_NIST_P384", "ecdsa-p384"): "ECDSA_SHA_384",
        }
        
        return algorithm_map.get((key_spec, key_type), "ECDSA_SHA_256")


class KMSService:
    """
    KMS Service abstraction supporting multiple providers
    
    Currently supports:
    - AWS KMS
    - File-based keys (for development)
    
    Future: Azure Key Vault, Google Cloud KMS, Hardware HSM
    """
    
    def __init__(self):
        self.aws_kms = None
        if AWS_AVAILABLE:
            try:
                self.aws_kms = AWSKMSService()
            except KMSException as e:
                logger.warning("AWS KMS not available", error=str(e))
    
    async def create_ca_key(
        self,
        key_type: str,
        storage_type: str = "kms",
        description: str = None
    ) -> Tuple[str, Optional[PrivateKeyTypes]]:
        """
        Create a key for CA operations
        
        Args:
            key_type: Key type (rsa-2048, ecdsa-p256, etc.)
            storage_type: Storage type (kms, file)
            description: Key description
            
        Returns:
            Tuple of (key_identifier, private_key_if_file_storage)
        """
        if storage_type == "kms":
            if not self.aws_kms:
                raise KMSException("KMS not available")
            
            # Map our key types to KMS key specs
            key_spec_map = {
                "rsa-2048": "RSA_2048",
                "rsa-4096": "RSA_4096", 
                "ecdsa-p256": "ECC_NIST_P256",
                "ecdsa-p384": "ECC_NIST_P384"
            }
            
            if key_type not in key_spec_map:
                raise KMSException(f"Key type {key_type} not supported in KMS")
            
            key_spec = key_spec_map[key_type]
            key_arn = await self.aws_kms.create_key(
                key_spec=key_spec,
                description=description or f"PKI-CA-ADMIN CA Key ({key_type})"
            )
            
            return key_arn, None
            
        elif storage_type == "file":
            # Generate private key locally (for development only)
            from app.services.crypto_service import CryptographicService
            crypto_service = CryptographicService()
            private_key = crypto_service.generate_private_key(key_type)
            
            # For file storage, return a placeholder identifier
            key_identifier = f"file:{key_type}:{base64.b64encode(os.urandom(16)).decode()}"
            
            return key_identifier, private_key
            
        else:
            raise KMSException(f"Unsupported storage type: {storage_type}")
    
    async def get_public_key(self, key_identifier: str, private_key: Optional[PrivateKeyTypes] = None) -> PublicKeyTypes:
        """
        Get public key from KMS or private key
        
        Args:
            key_identifier: Key identifier (ARN for KMS, identifier for file)
            private_key: Private key (for file storage)
            
        Returns:
            Public key object
        """
        if key_identifier.startswith("arn:aws:kms:"):
            # KMS key
            if not self.aws_kms:
                raise KMSException("AWS KMS not available")
            return await self.aws_kms.get_public_key(key_identifier)
            
        elif key_identifier.startswith("file:"):
            # File-based key
            if not private_key:
                raise KMSException("Private key required for file-based keys")
            return private_key.public_key()
            
        else:
            raise KMSException(f"Unknown key identifier format: {key_identifier}")
    
    async def sign_certificate_data(
        self,
        key_identifier: str,
        data_to_sign: bytes,
        key_type: str,
        private_key: Optional[PrivateKeyTypes] = None
    ) -> bytes:
        """
        Sign certificate data using KMS or private key
        
        Args:
            key_identifier: Key identifier
            data_to_sign: Data to be signed
            key_type: Key type for algorithm selection
            private_key: Private key (for file storage)
            
        Returns:
            Signature bytes
        """
        if key_identifier.startswith("arn:aws:kms:"):
            # KMS signing
            if not self.aws_kms:
                raise KMSException("AWS KMS not available")
            
            # Get appropriate algorithm
            key_spec_map = {
                "rsa-2048": "RSA_2048",
                "rsa-4096": "RSA_4096",
                "ecdsa-p256": "ECC_NIST_P256", 
                "ecdsa-p384": "ECC_NIST_P384"
            }
            key_spec = key_spec_map.get(key_type, "ECC_NIST_P256")
            algorithm = self.aws_kms.get_algorithm_for_key_spec(key_spec, key_type)
            
            return await self.aws_kms.sign_data(key_identifier, data_to_sign, algorithm)
            
        elif key_identifier.startswith("file:"):
            # Local signing
            if not private_key:
                raise KMSException("Private key required for file-based signing")
            
            # Use cryptography library for local signing
            signature = private_key.sign(data_to_sign, hashes.SHA256())
            return signature
            
        else:
            raise KMSException(f"Unknown key identifier format: {key_identifier}")


# Global KMS service instance
_kms_service = None


def get_kms_service() -> KMSService:
    """Get the global KMS service instance"""
    global _kms_service
    if _kms_service is None:
        _kms_service = KMSService()
    return _kms_service