"""Test configuration and fixtures for PKI CA Admin tests."""

import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import get_db, Base
from app.core.security import get_current_user, CurrentUser

# Test database URL - use in-memory SQLite for speed
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Create test engine
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False
)

# Test session factory
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create session
    async with TestSessionLocal() as session:
        yield session
    
    # Drop tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Override the get_db dependency."""
    async def _override_get_db():
        yield db_session
    return _override_get_db


@pytest.fixture
def mock_current_user():
    """Mock current user for authentication tests."""
    return CurrentUser({
        "sub": "test-user-id",
        "preferred_username": "testuser",
        "email": "test@example.com",
        "given_name": "Test",
        "family_name": "User",
        "realm_access": {
            "roles": ["admin", "operator", "viewer"]
        }
    })


@pytest.fixture
def override_get_current_user(mock_current_user: CurrentUser):
    """Override the get_current_user dependency."""
    async def _override_get_current_user():
        return mock_current_user
    return _override_get_current_user


@pytest.fixture
async def test_client(
    override_get_db,
    override_get_current_user
) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with database and authentication overrides."""
    
    # Override dependencies
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    # Clean up overrides
    app.dependency_overrides.clear()


@pytest.fixture
async def test_client_no_auth(
    override_get_db
) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client without authentication (for testing auth failures)."""
    
    # Only override database
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    # Clean up overrides
    app.dependency_overrides.clear()


# Test data fixtures
@pytest.fixture
def sample_ca_data():
    """Sample CA creation data."""
    return {
        "name": "Test Root CA",
        "description": "Test root certificate authority",
        "type": "root",
        "subject": {
            "common_name": "Test Root CA",
            "organization": "Test Organization",
            "organizational_unit": "IT Department",
            "country": "US",
            "state": "California",
            "locality": "San Francisco"
        },
        "key_type": "ecdsa-p256",
        "key_storage": "file",
        "validity_years": 10,
        "policy": {
            "max_path_length": 2,
            "allowed_key_types": ["rsa-2048", "ecdsa-p256"],
            "max_validity_days": 365
        }
    }


@pytest.fixture
def sample_certificate_data():
    """Sample certificate issuance data."""
    return {
        "common_name": "test.example.com",
        "certificate_type": "server",
        "subject_alternative_names": {
            "dns": ["test.example.com", "www.test.example.com"],
            "ip": ["192.168.1.100"]
        },
        "key_type": "ecdsa-p256",
        "validity_days": 365,
        "organization": "Test Organization",
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["server_auth"]
    }