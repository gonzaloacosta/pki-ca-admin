"""
API endpoints for PKI import operations.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import uuid
import base64

from fastapi import APIRouter, Depends, HTTPException, status, File, UploadFile, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import CurrentUser, require_admin
from app.models import CaNode, Certificate, AuditEvent
from app.services.import_service import ImportService, ImportError, InvalidFormatError, CertificateKeyMismatchError

router = APIRouter(prefix="/import", tags=["Import"])


class ImportPKCS12Request(BaseModel):
    """Request schema for PKCS#12 import."""
    pkcs12_data: str  # Base64-encoded PKCS#12 data
    password: Optional[str] = None
    ca_name: Optional[str] = None


class ImportPEMRequest(BaseModel):
    """Request schema for PEM import."""
    certificate_pem: str
    private_key_pem: Optional[str] = None
    private_key_password: Optional[str] = None
    ca_name: Optional[str] = None


class ImportResponse(BaseModel):
    """Response schema for import operations."""
    success: bool
    message: str
    ca_id: Optional[uuid.UUID] = None
    imported_cas: int = 0
    imported_certificates: int = 0
    warnings: list = []
    details: Dict[str, Any] = {}


@router.post("/pkcs12", response_model=ImportResponse, status_code=status.HTTP_201_CREATED)
async def import_pkcs12(
    import_request: ImportPKCS12Request,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Import a CA from PKCS#12 file.
    """
    try:
        # Decode base64 data
        try:
            pkcs12_data = base64.b64decode(import_request.pkcs12_data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 data: {str(e)}"
            )
        
        # Initialize import service
        import_service = ImportService()
        
        # Import from PKCS#12
        import_result = await import_service.import_ca_from_pkcs12(
            pkcs12_data=pkcs12_data,
            password=import_request.password,
            ca_name=import_request.ca_name
        )
        
        if not import_result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PKCS#12 import failed"
            )
        
        # Create CA record
        cert_info = import_result['ca_certificate']
        ca = CaNode(
            name=import_request.ca_name or cert_info['subject']['common_name'] or f"Imported CA {uuid.uuid4()}",
            description=f"Imported from PKCS#12 on {datetime.utcnow().isoformat()}",
            type="root" if cert_info['is_self_signed'] else "intermediate",
            subject_dn=cert_info['subject_dn'],
            certificate_pem=cert_info['certificate_pem'],
            serial_number=cert_info['serial_number'],
            not_before=cert_info['not_before'],
            not_after=cert_info['not_after'],
            key_type=cert_info['key_type'],
            key_storage="file",
            kms_key_id=import_result['key_id'],
            status="active",
            created_by=current_user.user_id
        )
        
        db.add(ca)
        await db.commit()
        await db.refresh(ca)
        
        # Create audit event
        audit_event = AuditEvent.create_ca_event(
            event_type="ca.imported",
            ca_id=ca.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_name": ca.name,
                "import_source": "pkcs12",
                "has_private_key": import_result['has_private_key'],
                "additional_certificates": import_result['additional_certificates']
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Build warnings
        warnings = []
        if not import_result['has_private_key']:
            warnings.append("No private key found - CA can only verify certificates, not issue new ones")
        
        return ImportResponse(
            success=True,
            message=f"Successfully imported CA: {ca.name}",
            ca_id=ca.id,
            imported_cas=1,
            imported_certificates=import_result['additional_certificates'],
            warnings=warnings,
            details=import_result
        )
        
    except HTTPException:
        raise
    except (InvalidFormatError, CertificateKeyMismatchError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Import failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import PKCS#12: {str(e)}"
        )


@router.post("/pem", response_model=ImportResponse, status_code=status.HTTP_201_CREATED)
async def import_pem(
    import_request: ImportPEMRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Import a CA from PEM files.
    """
    try:
        # Initialize import service
        import_service = ImportService()
        
        # Import from PEM
        import_result = await import_service.import_ca_from_pem(
            certificate_pem=import_request.certificate_pem,
            private_key_pem=import_request.private_key_pem,
            private_key_password=import_request.private_key_password,
            ca_name=import_request.ca_name
        )
        
        if not import_result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PEM import failed"
            )
        
        # Create CA record
        cert_info = import_result['ca_certificate']
        ca = CaNode(
            name=import_request.ca_name or cert_info['subject']['common_name'] or f"Imported CA {uuid.uuid4()}",
            description=f"Imported from PEM on {datetime.utcnow().isoformat()}",
            type="root" if cert_info['is_self_signed'] else "intermediate",
            subject_dn=cert_info['subject_dn'],
            certificate_pem=cert_info['certificate_pem'],
            serial_number=cert_info['serial_number'],
            not_before=cert_info['not_before'],
            not_after=cert_info['not_after'],
            key_type=cert_info['key_type'],
            key_storage="file",
            kms_key_id=import_result['key_id'],
            status="active",
            created_by=current_user.user_id
        )
        
        db.add(ca)
        await db.commit()
        await db.refresh(ca)
        
        # Create audit event
        audit_event = AuditEvent.create_ca_event(
            event_type="ca.imported",
            ca_id=ca.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_name": ca.name,
                "import_source": "pem",
                "has_private_key": import_result['has_private_key'],
                "additional_certificates": import_result['additional_certificates']
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Build warnings
        warnings = []
        if not import_result['has_private_key']:
            warnings.append("No private key provided - CA can only verify certificates, not issue new ones")
        
        return ImportResponse(
            success=True,
            message=f"Successfully imported CA: {ca.name}",
            ca_id=ca.id,
            imported_cas=1,
            imported_certificates=import_result.get('additional_certificates', 0),
            warnings=warnings,
            details=import_result
        )
        
    except HTTPException:
        raise
    except (InvalidFormatError, CertificateKeyMismatchError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Import failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import PEM: {str(e)}"
        )


@router.post("/pkcs12-file", response_model=ImportResponse, status_code=status.HTTP_201_CREATED)
async def import_pkcs12_file(
    file: UploadFile = File(..., description="PKCS#12 file"),
    password: Optional[str] = Form(None, description="PKCS#12 password"),
    ca_name: Optional[str] = Form(None, description="CA name"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Import a CA from uploaded PKCS#12 file.
    """
    try:
        # Validate file type
        if not file.filename.lower().endswith(('.p12', '.pfx')):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be a PKCS#12 file (.p12 or .pfx)"
            )
        
        # Read file content
        try:
            pkcs12_data = await file.read()
            if len(pkcs12_data) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Empty file"
                )
            if len(pkcs12_data) > 10 * 1024 * 1024:  # 10MB limit
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File too large (max 10MB)"
                )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read file: {str(e)}"
            )
        
        # Initialize import service
        import_service = ImportService()
        
        # Import from PKCS#12
        import_result = await import_service.import_ca_from_pkcs12(
            pkcs12_data=pkcs12_data,
            password=password,
            ca_name=ca_name
        )
        
        if not import_result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PKCS#12 import failed"
            )
        
        # Create CA record
        cert_info = import_result['ca_certificate']
        ca = CaNode(
            name=ca_name or cert_info['subject']['common_name'] or f"Imported CA {uuid.uuid4()}",
            description=f"Imported from PKCS#12 file '{file.filename}' on {datetime.utcnow().isoformat()}",
            type="root" if cert_info['is_self_signed'] else "intermediate",
            subject_dn=cert_info['subject_dn'],
            certificate_pem=cert_info['certificate_pem'],
            serial_number=cert_info['serial_number'],
            not_before=cert_info['not_before'],
            not_after=cert_info['not_after'],
            key_type=cert_info['key_type'],
            key_storage="file",
            kms_key_id=import_result['key_id'],
            status="active",
            created_by=current_user.user_id
        )
        
        db.add(ca)
        await db.commit()
        await db.refresh(ca)
        
        # Create audit event
        audit_event = AuditEvent.create_ca_event(
            event_type="ca.imported",
            ca_id=ca.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_name": ca.name,
                "import_source": "pkcs12_file",
                "filename": file.filename,
                "has_private_key": import_result['has_private_key'],
                "additional_certificates": import_result['additional_certificates']
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Build warnings
        warnings = []
        if not import_result['has_private_key']:
            warnings.append("No private key found - CA can only verify certificates, not issue new ones")
        
        return ImportResponse(
            success=True,
            message=f"Successfully imported CA from file: {ca.name}",
            ca_id=ca.id,
            imported_cas=1,
            imported_certificates=import_result['additional_certificates'],
            warnings=warnings,
            details=import_result
        )
        
    except HTTPException:
        raise
    except (InvalidFormatError, CertificateKeyMismatchError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Import failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import PKCS#12 file: {str(e)}"
        )


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_certificates(
    certificates_pem: str,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Analyze certificate hierarchy without importing.
    """
    try:
        # Initialize import service
        import_service = ImportService()
        
        # Parse certificates
        certificates = import_service.parse_pem_certificates(certificates_pem)
        
        # Analyze hierarchy
        hierarchy_info = import_service.analyze_ca_hierarchy(certificates)
        
        # Extract detailed information for each certificate
        certificate_details = []
        for cert in certificates:
            cert_info = import_service.extract_certificate_info(cert)
            certificate_details.append(cert_info)
        
        return {
            "success": True,
            "hierarchy": hierarchy_info,
            "certificates": certificate_details
        }
        
    except InvalidFormatError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze certificates: {str(e)}"
        )