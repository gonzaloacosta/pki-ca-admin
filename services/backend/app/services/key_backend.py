"""
Key Backend - Abstract interface for key storage with file-based implementation.
Designed for easy swap to KMS/HSM in the future.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import os
import uuid
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.config import get_settings

settings = get_settings()


class KeyBackendError(Exception):
    """Base exception for key backend operations."""
    pass


class KeyNotFoundError(KeyBackendError):
    """Key not found in backend."""
    pass


class KeyStorageError(KeyBackendError):
    """Error storing key in backend."""
    pass


class KeyLoadError(KeyBackendError):
    """Error loading key from backend."""
    pass


class KeyBackend(ABC):
    """Abstract base class for key storage backends."""
    
    @abstractmethod
    async def store_private_key(
        self, 
        private_key: PrivateKeyTypes, 
        key_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store a private key securely.
        
        Args:
            private_key: The private key to store
            key_id: Unique identifier for the key
            metadata: Optional metadata about the key
            
        Returns:
            str: Key reference/identifier for future retrieval
            
        Raises:
            KeyStorageError: If key cannot be stored
        """
        pass
    
    @abstractmethod
    async def load_private_key(self, key_reference: str) -> PrivateKeyTypes:
        """
        Load a private key.
        
        Args:
            key_reference: Key reference returned by store_private_key
            
        Returns:
            PrivateKeyTypes: The loaded private key
            
        Raises:
            KeyNotFoundError: If key is not found
            KeyLoadError: If key cannot be loaded
        """
        pass
    
    @abstractmethod
    async def delete_private_key(self, key_reference: str) -> bool:
        """
        Delete a private key.
        
        Args:
            key_reference: Key reference to delete
            
        Returns:
            bool: True if deleted, False if not found
            
        Raises:
            KeyBackendError: If deletion fails
        """
        pass
    
    @abstractmethod
    async def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """
        List all stored keys with metadata.
        
        Returns:
            Dict[str, Dict[str, Any]]: Mapping of key_reference -> metadata
        """
        pass
    
    @abstractmethod
    async def key_exists(self, key_reference: str) -> bool:
        """
        Check if a key exists.
        
        Args:
            key_reference: Key reference to check
            
        Returns:
            bool: True if key exists
        """
        pass


class FileKeyBackend(KeyBackend):
    """
    File-based key storage backend for development.
    Keys are encrypted with PBKDF2 and stored on disk.
    
    WARNING: This is for development only. Use KMS/HSM for production.
    """
    
    def __init__(self, storage_path: str, encryption_password: str):
        """
        Initialize file key backend.
        
        Args:
            storage_path: Directory to store encrypted keys
            encryption_password: Password for key encryption
        """
        self.storage_path = Path(storage_path)
        self.encryption_password = encryption_password.encode()
        
        # Ensure storage directory exists
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Metadata file
        self.metadata_file = self.storage_path / "metadata.json"
        
    async def store_private_key(
        self, 
        private_key: PrivateKeyTypes, 
        key_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store private key encrypted to disk."""
        try:
            # Generate unique filename
            key_reference = f"{key_id}-{uuid.uuid4().hex}"
            key_file = self.storage_path / f"{key_reference}.key"
            
            # Generate salt for encryption
            salt = os.urandom(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            encryption_key = kdf.derive(self.encryption_password)
            
            # Serialize private key
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
            )
            
            # Store key file with salt
            key_data = {
                "salt": salt.hex(),
                "encrypted_key": private_key_bytes.decode('utf-8')
            }
            
            with open(key_file, 'w') as f:
                json.dump(key_data, f, indent=2)

            # Restrict file permissions (best-effort on Windows)
            try:
                key_file.chmod(0o600)
            except OSError:
                pass
            
            # Update metadata
            await self._update_metadata(key_reference, {
                "key_id": key_id,
                "created_at": str(uuid.uuid1().time),
                "key_file": str(key_file.name),
                "metadata": metadata or {}
            })
            
            return key_reference
            
        except Exception as e:
            raise KeyStorageError(f"Failed to store private key: {str(e)}")
    
    async def load_private_key(self, key_reference: str) -> PrivateKeyTypes:
        """Load encrypted private key from disk."""
        try:
            key_file = self.storage_path / f"{key_reference}.key"
            
            if not key_file.exists():
                raise KeyNotFoundError(f"Key file not found: {key_reference}")
            
            # Load key data
            with open(key_file, 'r') as f:
                key_data = json.load(f)
            
            # Derive decryption key
            salt = bytes.fromhex(key_data["salt"])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            encryption_key = kdf.derive(self.encryption_password)
            
            # Load private key
            encrypted_key_bytes = key_data["encrypted_key"].encode('utf-8')
            private_key = serialization.load_pem_private_key(
                encrypted_key_bytes,
                password=encryption_key
            )
            
            return private_key
            
        except KeyNotFoundError:
            raise
        except Exception as e:
            raise KeyLoadError(f"Failed to load private key: {str(e)}")
    
    async def delete_private_key(self, key_reference: str) -> bool:
        """Delete private key from disk."""
        try:
            key_file = self.storage_path / f"{key_reference}.key"
            
            if not key_file.exists():
                return False
            
            # Remove key file
            key_file.unlink()
            
            # Remove from metadata
            await self._remove_from_metadata(key_reference)
            
            return True
            
        except Exception as e:
            raise KeyBackendError(f"Failed to delete private key: {str(e)}")
    
    async def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """List all stored keys."""
        try:
            return await self._load_metadata()
        except Exception as e:
            raise KeyBackendError(f"Failed to list keys: {str(e)}")
    
    async def key_exists(self, key_reference: str) -> bool:
        """Check if key exists."""
        key_file = self.storage_path / f"{key_reference}.key"
        return key_file.exists()
    
    async def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load metadata from file."""
        if not self.metadata_file.exists():
            return {}
        
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    async def _save_metadata(self, metadata: Dict[str, Dict[str, Any]]) -> None:
        """Save metadata to file."""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Secure the metadata file
        self.metadata_file.chmod(0o600)
    
    async def _update_metadata(self, key_reference: str, key_metadata: Dict[str, Any]) -> None:
        """Update metadata for a key."""
        metadata = await self._load_metadata()
        metadata[key_reference] = key_metadata
        await self._save_metadata(metadata)
    
    async def _remove_from_metadata(self, key_reference: str) -> None:
        """Remove key from metadata."""
        metadata = await self._load_metadata()
        metadata.pop(key_reference, None)
        await self._save_metadata(metadata)


class KMSKeyBackend(KeyBackend):
    """
    AWS KMS key backend for production use.
    
    Note: This is a placeholder implementation.
    In production, this would use boto3 to interact with AWS KMS.
    """
    
    def __init__(self, aws_region: str, kms_key_id: Optional[str] = None):
        self.aws_region = aws_region
        self.kms_key_id = kms_key_id
        
        # TODO: Initialize boto3 KMS client
        raise NotImplementedError("KMS backend not yet implemented")
    
    async def store_private_key(
        self, 
        private_key: PrivateKeyTypes, 
        key_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        # TODO: Implement KMS key storage
        raise NotImplementedError("KMS backend not yet implemented")
    
    async def load_private_key(self, key_reference: str) -> PrivateKeyTypes:
        # TODO: Implement KMS key loading
        raise NotImplementedError("KMS backend not yet implemented")
    
    async def delete_private_key(self, key_reference: str) -> bool:
        # TODO: Implement KMS key deletion
        raise NotImplementedError("KMS backend not yet implemented")
    
    async def list_keys(self) -> Dict[str, Dict[str, Any]]:
        # TODO: Implement KMS key listing
        raise NotImplementedError("KMS backend not yet implemented")
    
    async def key_exists(self, key_reference: str) -> bool:
        # TODO: Implement KMS key existence check
        raise NotImplementedError("KMS backend not yet implemented")


class HSMKeyBackend(KeyBackend):
    """
    Hardware Security Module (HSM) key backend.
    
    Note: This is a placeholder implementation.
    In production, this would use PKCS#11 libraries to interact with HSM.
    """
    
    def __init__(self, hsm_config: Dict[str, Any]):
        self.hsm_config = hsm_config
        
        # TODO: Initialize HSM connection
        raise NotImplementedError("HSM backend not yet implemented")
    
    async def store_private_key(
        self, 
        private_key: PrivateKeyTypes, 
        key_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        # TODO: Implement HSM key storage
        raise NotImplementedError("HSM backend not yet implemented")
    
    async def load_private_key(self, key_reference: str) -> PrivateKeyTypes:
        # TODO: Implement HSM key loading
        raise NotImplementedError("HSM backend not yet implemented")
    
    async def delete_private_key(self, key_reference: str) -> bool:
        # TODO: Implement HSM key deletion
        raise NotImplementedError("HSM backend not yet implemented")
    
    async def list_keys(self) -> Dict[str, Dict[str, Any]]:
        # TODO: Implement HSM key listing
        raise NotImplementedError("HSM backend not yet implemented")
    
    async def key_exists(self, key_reference: str) -> bool:
        # TODO: Implement HSM key existence check
        raise NotImplementedError("HSM backend not yet implemented")


# Factory function to get the appropriate backend
def get_key_backend() -> KeyBackend:
    """
    Get the configured key backend.
    
    Returns:
        KeyBackend: Configured key backend instance
    """
    backend_type = settings.key_backend.lower()
    
    if backend_type == "file":
        return FileKeyBackend(
            storage_path=settings.file_key_storage_path,
            encryption_password=settings.file_key_encryption_password
        )
    elif backend_type == "kms":
        return KMSKeyBackend(
            aws_region=settings.aws_region,
            kms_key_id=settings.kms_key_id
        )
    elif backend_type == "hsm":
        # HSM config would come from settings
        hsm_config = {}  # TODO: Load from settings
        return HSMKeyBackend(hsm_config)
    else:
        raise ValueError(f"Unknown key backend type: {backend_type}")


# Synchronous version for backwards compatibility
def store_private_key(private_key: PrivateKeyTypes, key_id: str) -> str:
    """Synchronous wrapper for storing private key."""
    import asyncio
    backend = get_key_backend()
    return asyncio.run(backend.store_private_key(private_key, key_id))


def load_private_key(key_reference: str) -> PrivateKeyTypes:
    """Synchronous wrapper for loading private key."""
    import asyncio
    backend = get_key_backend()
    return asyncio.run(backend.load_private_key(key_reference))