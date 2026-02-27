# Development Setup & Testing Guide

## Prerequisites

- **Docker Desktop** running
- **curl** (or any HTTP client)
- No local PostgreSQL on port 5432 (or disable it first)

## Start the Dev Environment

```bash
docker compose -f infra/docker/docker-compose.dev.yml up -d
```

Wait for all services to be healthy:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

You should see three containers running:

| Container | Port | Purpose |
|-----------|------|---------|
| `pki-postgres-dev` | 5432 | PostgreSQL 16 (app + Keycloak databases) |
| `pki-keycloak-dev` | 8080 | Keycloak 24 (identity provider) |
| `pki-backend-dev` | 8000 | FastAPI backend |

> **Keycloak takes ~30-60 seconds** to fully start and import realms. If token requests fail immediately after startup, wait a moment and retry.

## Step 1 - Verify Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Backend root info
curl http://localhost:8000/

# Keycloak realm discovery
curl http://localhost:8080/realms/pki-ca-admin/.well-known/openid-configuration
```

All three should return JSON responses.

## Step 2 - Get an Authentication Token

Tokens are obtained from Keycloak using the OAuth2 Resource Owner Password flow.

**Linux / macOS / Git Bash:**

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/realms/pki-ca-admin/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=pki-api" \
  -d "client_secret=pki-api-client-secret" \
  -d "username=admin" \
  -d "password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Windows CMD:**

```cmd
curl -s -X POST http://localhost:8080/realms/pki-ca-admin/protocol/openid-connect/token ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "grant_type=password" ^
  -d "client_id=pki-api" ^
  -d "client_secret=pki-api-client-secret" ^
  -d "username=admin" ^
  -d "password=admin123"
```

Copy the `access_token` value from the JSON response for use in subsequent requests.

**Windows PowerShell:**

```powershell
$response = Invoke-RestMethod -Method Post -Uri "http://localhost:8080/realms/pki-ca-admin/protocol/openid-connect/token" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "grant_type=password&client_id=pki-api&client_secret=pki-api-client-secret&username=admin&password=admin123"
$TOKEN = $response.access_token
```

## Step 3 - Test Unauthenticated Access

Requests without a token should be rejected:

```bash
curl -s http://localhost:8000/api/v1/cas
```

Expected: `403 Forbidden` or `{"detail": "Not authenticated"}`.

## Step 4 - List Certificate Authorities

```bash
curl -s http://localhost:8000/api/v1/cas \
  -H "Authorization: Bearer $TOKEN"
```

Expected: `{"items":[], "total":0, "page":1, "size":20, "pages":0}` (empty on fresh start).

## Step 5 - Create a Root CA

```bash
curl -s -X POST http://localhost:8000/api/v1/cas \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Root CA",
    "type": "root",
    "key_type": "ecdsa-p256",
    "subject": {
      "common_name": "My Root CA",
      "organization": "My Organization",
      "country": "US"
    },
    "validity_years": 10
  }'
```

Expected: `201 Created` with the full CA object, including:
- A real PEM-encoded X.509 certificate (`certificate_pem`)
- ECDSA P-256 key pair (private key stored encrypted on disk)
- 10-year validity period
- `"status": "active"`

## Step 6 - Verify the CA Exists

```bash
# List all CAs
curl -s http://localhost:8000/api/v1/cas \
  -H "Authorization: Bearer $TOKEN"

# Get CA statistics
curl -s http://localhost:8000/api/v1/cas/stats \
  -H "Authorization: Bearer $TOKEN"
```

Stats should show `"total_cas": 1, "root_cas": 1, "active_cas": 1`.

## Step 7 - Test RBAC (Role-Based Access Control)

The system enforces three roles with different permissions:

| Role | Create CA | Read CA | Update CA | Delete CA |
|------|-----------|---------|-----------|-----------|
| admin | Yes | Yes | Yes | Yes |
| operator | No | Yes | No | No |
| viewer | No | Yes | No | No |

### Test as viewer (read-only):

Get a viewer token:

```bash
VIEWER_TOKEN=$(curl -s -X POST http://localhost:8080/realms/pki-ca-admin/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=pki-api" \
  -d "client_secret=pki-api-client-secret" \
  -d "username=viewer" \
  -d "password=viewer123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Viewer CAN list CAs:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  http://localhost:8000/api/v1/cas \
  -H "Authorization: Bearer $VIEWER_TOKEN"
# Expected: HTTP 200
```

Viewer CANNOT create CAs:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/api/v1/cas \
  -H "Authorization: Bearer $VIEWER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Should Fail","type":"root","subject":{"common_name":"Fail"},"validity_years":1}'
# Expected: HTTP 403
```

## Available Test Users

### Default Realm (`pki-ca-admin`)

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| operator | operator123 | operator |
| viewer | viewer123 | viewer |

### Team Alpha Realm (`team-alpha`)

| Username | Password | Role | Groups |
|----------|----------|------|--------|
| alpha-admin | alpha-admin-123 | admin | prod |
| alpha-dev-ops | alpha-devops-123 | operator | dev, staging |
| alpha-developer | alpha-dev-123 | viewer | dev |

### Team Beta Realm (`team-beta`)

| Username | Password | Role | Groups |
|----------|----------|------|--------|
| beta-admin | beta-admin-123 | admin | prod |
| beta-staging-ops | beta-staging-123 | operator | staging |
| beta-viewer | beta-viewer-123 | viewer | all groups |

> To use a different realm, replace `pki-ca-admin` with `team-alpha` or `team-beta` in the token URL.

## API Reference

### Public Endpoints (no auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Application info |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

### Certificate Authorities (`/api/v1/cas`)

| Method | Endpoint | Min Role | Description |
|--------|----------|----------|-------------|
| GET | `/api/v1/cas` | viewer | List CAs (paginated) |
| GET | `/api/v1/cas/stats` | viewer | CA statistics |
| GET | `/api/v1/cas/tree` | viewer | CA hierarchy tree |
| GET | `/api/v1/cas/{id}` | viewer | Get CA by ID |
| POST | `/api/v1/cas` | admin | Create new CA |
| PUT | `/api/v1/cas/{id}` | admin | Update CA |
| DELETE | `/api/v1/cas/{id}` | admin | Revoke CA (soft delete) |

### Certificates (`/api/v1/certificates`)

| Method | Endpoint | Min Role | Description |
|--------|----------|----------|-------------|
| GET | `/api/v1/certificates` | viewer | List certificates |
| POST | `/api/v1/certificates/{ca_id}/issue` | operator | Issue certificate |
| POST | `/api/v1/certificates/{ca_id}/sign-csr` | operator | Sign CSR |
| POST | `/api/v1/certificates/{id}/revoke` | operator | Revoke certificate |

### Audit (`/api/v1/audit`)

| Method | Endpoint | Min Role | Description |
|--------|----------|----------|-------------|
| GET | `/api/v1/audit` | viewer | List audit events |
| GET | `/api/v1/audit/stats` | viewer | Audit statistics |
| GET | `/api/v1/audit/search` | viewer | Search audit events |

## Supported Key Types

| Key Type | Value | Use Case |
|----------|-------|----------|
| ECDSA P-256 | `ecdsa-p256` | Recommended default |
| ECDSA P-384 | `ecdsa-p384` | Higher security |
| RSA 2048 | `rsa-2048` | Legacy compatibility |
| RSA 3072 | `rsa-3072` | Stronger RSA |
| RSA 4096 | `rsa-4096` | Maximum RSA strength |
| Ed25519 | `ed25519` | Modern, fast |

## Teardown

```bash
# Stop containers (keep data)
docker compose -f infra/docker/docker-compose.dev.yml down

# Stop containers AND delete all data (clean start)
docker compose -f infra/docker/docker-compose.dev.yml down -v
```
