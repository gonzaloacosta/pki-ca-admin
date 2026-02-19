"""
step-ca integration service for PKI-CA-ADMIN

This service manages step-ca instances for each CA in the hierarchy.
It handles configuration generation, process management, and HTTP API integration.

Architecture:
- One step-ca instance per CA (root, intermediate, project-level)
- Each instance runs as a separate process with its own config and database
- HTTP API integration for certificate operations
- Process lifecycle management (start, stop, health monitoring)
"""

import json
import os
import subprocess
import signal
import time
import asyncio
import aiohttp
import tempfile
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import structlog

from app.core.config import settings
from app.models.database import CertificateAuthority
from app.services.crypto_service import CryptographicService

logger = structlog.get_logger()


class StepCAException(Exception):
    """step-ca operation exception"""
    pass


class StepCAInstance:
    """Manages a single step-ca instance"""
    
    def __init__(self, ca: CertificateAuthority, base_path: str = None):
        self.ca = ca
        self.ca_id = str(ca.id)
        self.base_path = Path(base_path or settings.STEPCA_BASE_PATH)
        self.instance_path = self.base_path / f"ca-{self.ca_id}"
        self.config_path = self.instance_path / "config"
        self.data_path = self.instance_path / "data" 
        self.config_file = self.config_path / "ca.json"
        self.password_file = self.config_path / "password.txt"
        self.port = self._get_port()
        self.process = None
        
        # Create directories
        self.config_path.mkdir(parents=True, exist_ok=True)
        self.data_path.mkdir(parents=True, exist_ok=True)
    
    def _get_port(self) -> int:
        """Get unique port for this CA instance"""
        # Base port 9000, add CA ID hash for uniqueness
        base_port = 9000
        ca_hash = hash(self.ca_id) % 1000
        return base_port + ca_hash
    
    async def initialize(self, crypto_service: CryptographicService) -> None:
        """
        Initialize step-ca instance with CA certificate and configuration
        
        Args:
            crypto_service: Cryptographic service for key/cert operations
        """
        try:
            logger.info("Initializing step-ca instance", ca_id=self.ca_id, ca_name=self.ca.name)
            
            # Generate configuration
            config = await self._generate_config()
            
            # Write configuration file
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Generate password for key protection
            password = self._generate_password()
            with open(self.password_file, 'w') as f:
                f.write(password)
            
            # Set up certificates and keys
            await self._setup_certificates(crypto_service, password)
            
            logger.info("step-ca instance initialized successfully", ca_id=self.ca_id)
            
        except Exception as e:
            logger.error("Failed to initialize step-ca instance", ca_id=self.ca_id, error=str(e))
            raise StepCAException(f"step-ca initialization failed: {str(e)}")
    
    async def _generate_config(self) -> Dict[str, Any]:
        """Generate step-ca configuration"""
        config = {
            "root": str(self.config_path / "root_ca.crt"),
            "federatedRoots": [],
            "crt": str(self.config_path / "intermediate_ca.crt" if self.ca.type == "intermediate" else "root_ca.crt"),
            "key": str(self.config_path / "ca_key.pem"),
            "address": f":{self.port}",
            "dnsNames": ["localhost", "127.0.0.1", f"ca-{self.ca_id}"],
            "logger": {"format": "json"},
            "db": {
                "type": "badgerv2",
                "dataSource": str(self.data_path / "db"),
                "badgerFileLoadingMode": ""
            },
            "authority": {
                "provisioners": await self._generate_default_provisioners(),
                "template": {},
                "backdate": "1m0s"
            },
            "tls": {
                "cipherSuites": [
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                ],
                "minVersion": 1.2,
                "maxVersion": 1.3,
                "renegotiation": False
            }
        }
        
        # Add CRL distribution points if configured
        if self.ca.crl_distribution_points:
            config["crl"] = {
                "enabled": True,
                "generateOnRevoke": True,
                "cacheDuration": "24h",
                "distributionPoints": self.ca.crl_distribution_points
            }
        
        # Add OCSP responder if configured
        if self.ca.ocsp_responder_url:
            config["authority"]["enableAdmin"] = True
        
        return config
    
    async def _generate_default_provisioners(self) -> List[Dict[str, Any]]:
        """Generate default provisioners for the CA"""
        provisioners = []
        
        # JWK provisioner for API access
        jwk_provisioner = {
            "type": "JWK",
            "name": f"{self.ca.name.replace(' ', '-').lower()}-jwk",
            "key": {
                "use": "sig",
                "kty": "EC",
                "kid": str(uuid.uuid4()),
                "crv": "P-256",
                "alg": "ES256"
                # Public key will be generated during setup
            },
            "claims": {
                "maxTLSCertDuration": f"{self.ca.max_validity_days * 24}h" if self.ca.max_validity_days else "8760h",
                "defaultTLSCertDuration": "720h"  # 30 days default
            }
        }
        
        # Generate JWK key pair
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        import base64
        
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        # Convert to JWK format
        public_numbers = public_key.public_numbers()
        curve = public_numbers.curve
        
        # Get coordinates
        x = public_numbers.x.to_bytes((curve.key_size + 7) // 8, byteorder='big')
        y = public_numbers.y.to_bytes((curve.key_size + 7) // 8, byteorder='big')
        
        jwk_provisioner["key"]["x"] = base64.urlsafe_b64encode(x).decode('ascii').rstrip('=')
        jwk_provisioner["key"]["y"] = base64.urlsafe_b64encode(y).decode('ascii').rstrip('=')
        
        # Store private key for later use
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        jwk_private_key_file = self.config_path / "jwk_provisioner.pem"
        with open(jwk_private_key_file, 'wb') as f:
            f.write(private_key_pem)
        
        provisioners.append(jwk_provisioner)
        
        # ACME provisioner if enabled
        acme_provisioner = {
            "type": "ACME",
            "name": f"{self.ca.name.replace(' ', '-').lower()}-acme",
            "claims": {
                "maxTLSCertDuration": f"{self.ca.max_validity_days * 24}h" if self.ca.max_validity_days else "8760h",
                "defaultTLSCertDuration": "720h"
            }
        }
        provisioners.append(acme_provisioner)
        
        return provisioners
    
    def _generate_password(self) -> str:
        """Generate secure password for key protection"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    async def _setup_certificates(self, crypto_service: CryptographicService, password: str) -> None:
        """Set up CA certificates and keys for step-ca"""
        try:
            # For file-based keys, generate locally
            if self.ca.key_storage == "file":
                if self.ca.type == "root":
                    # Generate self-signed root certificate
                    private_key = crypto_service.generate_private_key(self.ca.key_type)
                    certificate = crypto_service.generate_ca_certificate(self.ca, private_key)
                    
                    # Write root certificate
                    cert_pem = crypto_service.certificate_to_pem(certificate)
                    with open(self.config_path / "root_ca.crt", 'w') as f:
                        f.write(cert_pem)
                    
                    # Write private key (encrypted)
                    key_pem = crypto_service.private_key_to_pem(private_key, password.encode())
                    with open(self.config_path / "ca_key.pem", 'w') as f:
                        f.write(key_pem)
                
                elif self.ca.type == "intermediate":
                    # For intermediate CAs, we need the parent CA to sign
                    # This would be handled by the orchestration layer
                    pass
            else:
                # KMS-based keys
                # The certificates should already be in the database
                if self.ca.certificate_pem:
                    if self.ca.type == "root":
                        with open(self.config_path / "root_ca.crt", 'w') as f:
                            f.write(self.ca.certificate_pem)
                    else:
                        with open(self.config_path / "intermediate_ca.crt", 'w') as f:
                            f.write(self.ca.certificate_pem)
                        
                        # For intermediate CAs, also need root certificate
                        # This should be retrieved from the parent CA
                        # For now, create a placeholder
                        with open(self.config_path / "root_ca.crt", 'w') as f:
                            f.write("# Root certificate would be placed here")
        
        except Exception as e:
            raise StepCAException(f"Failed to setup certificates: {str(e)}")
    
    async def start(self) -> None:
        """Start the step-ca process"""
        if self.is_running():
            logger.warning("step-ca instance already running", ca_id=self.ca_id)
            return
        
        try:
            cmd = [
                "step-ca",
                str(self.config_file),
                "--password-file", str(self.password_file)
            ]
            
            # Start step-ca process
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.instance_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a bit for startup
            await asyncio.sleep(2)
            
            # Check if process is still running
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise StepCAException(f"step-ca failed to start: {stderr}")
            
            # Verify HTTP endpoint is responding
            if not await self._wait_for_health():
                raise StepCAException("step-ca health check failed")
            
            logger.info("step-ca instance started successfully", 
                       ca_id=self.ca_id, port=self.port, pid=self.process.pid)
        
        except Exception as e:
            if self.process:
                self.process.terminate()
                self.process = None
            logger.error("Failed to start step-ca instance", ca_id=self.ca_id, error=str(e))
            raise StepCAException(f"Failed to start step-ca: {str(e)}")
    
    async def stop(self) -> None:
        """Stop the step-ca process"""
        if not self.is_running():
            return
        
        try:
            # Graceful shutdown
            self.process.terminate()
            
            # Wait for shutdown
            try:
                await asyncio.wait_for(asyncio.to_thread(self.process.wait), timeout=10.0)
            except asyncio.TimeoutError:
                # Force kill if needed
                self.process.kill()
                await asyncio.to_thread(self.process.wait)
            
            self.process = None
            logger.info("step-ca instance stopped", ca_id=self.ca_id)
        
        except Exception as e:
            logger.error("Error stopping step-ca instance", ca_id=self.ca_id, error=str(e))
            raise StepCAException(f"Failed to stop step-ca: {str(e)}")
    
    def is_running(self) -> bool:
        """Check if step-ca process is running"""
        return self.process is not None and self.process.poll() is None
    
    async def _wait_for_health(self, timeout: int = 30) -> bool:
        """Wait for step-ca to become healthy"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://localhost:{self.port}/health", 
                                         timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            return True
            except:
                pass
            
            await asyncio.sleep(1)
        
        return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on step-ca instance"""
        if not self.is_running():
            return {"status": "stopped", "healthy": False}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://localhost:{self.port}/health", 
                                     timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {"status": "running", "healthy": True, "details": data}
                    else:
                        return {"status": "running", "healthy": False, "error": f"HTTP {response.status}"}
        
        except Exception as e:
            return {"status": "running", "healthy": False, "error": str(e)}
    
    async def issue_certificate(self, csr_pem: str, provisioner: str = None) -> Dict[str, Any]:
        """
        Issue certificate via step-ca HTTP API
        
        Args:
            csr_pem: Certificate signing request in PEM format
            provisioner: Provisioner name (uses default JWK if not specified)
            
        Returns:
            Certificate data
        """
        if not self.is_running():
            raise StepCAException("step-ca instance is not running")
        
        try:
            # Use default JWK provisioner if not specified
            if not provisioner:
                provisioner = f"{self.ca.name.replace(' ', '-').lower()}-jwk"
            
            # Prepare request data
            request_data = {
                "csr": csr_pem,
                "provisioner": provisioner
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://localhost:{self.port}/1.0/sign",
                    json=request_data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        return result
                    else:
                        error_text = await response.text()
                        raise StepCAException(f"Certificate issuance failed: {error_text}")
        
        except Exception as e:
            logger.error("Failed to issue certificate", ca_id=self.ca_id, error=str(e))
            raise StepCAException(f"Certificate issuance failed: {str(e)}")


class StepCAService:
    """
    Service for managing multiple step-ca instances
    
    This service orchestrates step-ca instances for the PKI hierarchy.
    Each CA gets its own step-ca instance for isolation and scalability.
    """
    
    def __init__(self):
        self.instances: Dict[str, StepCAInstance] = {}
        self.crypto_service = CryptographicService()
    
    async def create_ca_instance(self, ca: CertificateAuthority) -> StepCAInstance:
        """
        Create and initialize a step-ca instance for a CA
        
        Args:
            ca: Certificate Authority database object
            
        Returns:
            Initialized StepCAInstance
        """
        ca_id = str(ca.id)
        
        if ca_id in self.instances:
            logger.warning("step-ca instance already exists", ca_id=ca_id)
            return self.instances[ca_id]
        
        try:
            # Create instance
            instance = StepCAInstance(ca)
            
            # Initialize configuration and certificates
            await instance.initialize(self.crypto_service)
            
            # Store instance
            self.instances[ca_id] = instance
            
            logger.info("step-ca instance created", ca_id=ca_id, ca_name=ca.name)
            return instance
        
        except Exception as e:
            logger.error("Failed to create step-ca instance", ca_id=ca_id, error=str(e))
            raise StepCAException(f"Failed to create step-ca instance: {str(e)}")
    
    async def start_ca_instance(self, ca_id: str) -> None:
        """Start a step-ca instance"""
        if ca_id not in self.instances:
            raise StepCAException(f"step-ca instance not found: {ca_id}")
        
        await self.instances[ca_id].start()
    
    async def stop_ca_instance(self, ca_id: str) -> None:
        """Stop a step-ca instance"""
        if ca_id not in self.instances:
            raise StepCAException(f"step-ca instance not found: {ca_id}")
        
        await self.instances[ca_id].stop()
    
    async def get_instance_health(self, ca_id: str) -> Dict[str, Any]:
        """Get health status of a step-ca instance"""
        if ca_id not in self.instances:
            return {"status": "not_found", "healthy": False}
        
        return await self.instances[ca_id].health_check()
    
    async def issue_certificate_via_stepca(
        self, 
        ca_id: str, 
        csr_pem: str, 
        provisioner: str = None
    ) -> Dict[str, Any]:
        """Issue certificate via step-ca instance"""
        if ca_id not in self.instances:
            raise StepCAException(f"step-ca instance not found: {ca_id}")
        
        return await self.instances[ca_id].issue_certificate(csr_pem, provisioner)
    
    async def get_all_instances_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all step-ca instances"""
        status = {}
        
        for ca_id, instance in self.instances.items():
            try:
                status[ca_id] = await instance.health_check()
            except Exception as e:
                status[ca_id] = {"status": "error", "healthy": False, "error": str(e)}
        
        return status
    
    async def cleanup_instance(self, ca_id: str) -> None:
        """Clean up a step-ca instance (stop and remove)"""
        if ca_id in self.instances:
            try:
                await self.instances[ca_id].stop()
            except:
                pass  # Ignore errors during cleanup
            
            del self.instances[ca_id]
            logger.info("step-ca instance cleaned up", ca_id=ca_id)


# Global step-ca service instance
_stepca_service = None


def get_stepca_service() -> StepCAService:
    """Get the global step-ca service instance"""
    global _stepca_service
    if _stepca_service is None:
        _stepca_service = StepCAService()
    return _stepca_service