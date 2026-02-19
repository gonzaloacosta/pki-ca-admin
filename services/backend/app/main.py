"""
Main FastAPI application for PKI CA Admin.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from app.core.config import get_settings
from app.core.database import init_db, close_db
from app.api.v1 import cas, certificates, import_, audit

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.audit_log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events.
    """
    # Startup
    logger.info("Starting PKI CA Admin API")
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down PKI CA Admin API")
    await close_db()
    logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Certificate Authority Administration API",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_origin_regex=settings.allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for audit purposes."""
    start_time = time.time()
    
    # Skip logging for health checks
    if request.url.path in ["/health", "/health/ready"]:
        response = await call_next(request)
        return response
    
    # Extract client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} - "
        f"IP: {client_ip} - User-Agent: {user_agent}"
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Log response
    logger.info(
        f"Response: {request.method} {request.url.path} - "
        f"Status: {response.status_code} - Time: {process_time:.3f}s"
    )
    
    # Add processing time header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unexpected errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Health check endpoints
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": time.time()
    }


@app.get("/health/ready")
async def readiness_check():
    """Readiness check endpoint."""
    # TODO: Add database connectivity check
    return {
        "status": "ready",
        "service": settings.app_name,
        "version": settings.app_version,
        "database": "connected",  # TODO: Implement actual check
        "timestamp": time.time()
    }


# Include API routers
app.include_router(cas.router, prefix="/api/v1")
app.include_router(certificates.router, prefix="/api/v1")
app.include_router(import_.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "description": "Certificate Authority Administration API",
        "docs": "/docs" if settings.debug else "Documentation disabled in production",
        "health": "/health",
        "api": "/api/v1"
    }


# API info endpoint
@app.get("/api/v1")
async def api_info():
    """API version 1 information."""
    return {
        "version": "1.0",
        "endpoints": {
            "cas": "/api/v1/cas",
            "certificates": "/api/v1/certificates", 
            "import": "/api/v1/import",
            "audit": "/api/v1/audit"
        },
        "features": [
            "CA creation and management",
            "Certificate issuance and revocation",
            "PKI import (PKCS#12, PEM)",
            "Audit logging and reporting",
            "JWT-based authentication",
            "Role-based access control"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info"
    )