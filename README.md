# pki-ca-admin

> Certificate Authority Administration platform for managing multi-tier PKI hierarchies (Root CA → Environment Sub-CAs → Project Sub-CAs → Leaf Certificates). Focus on mTLS, change tracking, and API-driven certificate lifecycle automation. Developer-first, multi-cloud, with audit trail and compliance features.

## Quick Start

1. Start the development environment:
   ```bash
   docker compose -f infra/docker/docker-compose.dev.yml up -d
   ```

2. The services will be available at:
   - **FastAPI Backend**: http://localhost:8000
   - **API Documentation**: http://localhost:8000/docs
   - **Keycloak Admin**: http://localhost:8080 (admin/admin)
   - **PostgreSQL**: localhost:5432 (pki/pki_dev)

3. **Multi-Tenant Setup**: The system includes multiple Keycloak realms:
   - **Default realm** (`pki-ca-admin`): Basic setup with admin/operator/viewer users
   - **Team Alpha** (`team-alpha`): Example team realm with dev/staging/prod groups
   - **Team Beta** (`team-beta`): Example team realm with dev/staging/prod groups

4. **Test Users by Realm**:
   
   **Team Alpha (realm: team-alpha)**:
   - `alpha-admin` / `alpha-admin-123` (admin role, prod group)
   - `alpha-dev-ops` / `alpha-devops-123` (operator role, dev+staging groups)
   - `alpha-developer` / `alpha-dev-123` (viewer role, dev group)
   
   **Team Beta (realm: team-beta)**:
   - `beta-admin` / `beta-admin-123` (admin role, prod group)
   - `beta-staging-ops` / `beta-staging-123` (operator role, staging group)
   - `beta-viewer` / `beta-viewer-123` (viewer role, all groups)

5. Access the API documentation at http://localhost:8000/docs to explore the endpoints.

## Multi-Tenancy Architecture

- **Realm = Tenant**: Each Keycloak realm represents a separate tenant with complete isolation
- **Groups = CA Scope**: Groups within a realm determine which CAs a user can access
- **Roles = Permissions**: Roles define what actions a user can perform (admin/operator/viewer)
- **Database Isolation**: All data is filtered by `tenant_id` extracted from JWT token realm

## Architecture

See [docs/architecture/](docs/architecture/) for detailed design documents.

## Structure

```
├── services/
│   ├── backend/          # Backend API
│   └── frontend/         # Frontend app
├── infra/
│   ├── terraform/        # Infrastructure as Code
│   ├── kubernetes/       # K8s manifests
│   └── docker/           # Docker configs
├── docs/                 # Documentation
├── scripts/              # Automation scripts
└── .claude/              # AI agent configuration
    ├── agents/           # 7 sub-agents (backend, frontend, devops, devsecops, qa, reviewer, planner)
    ├── rules/            # Contextual rules (code-quality, security, testing, git-workflow)
    ├── skills/           # Slash commands (/review, /plan, /deploy, /status)
    └── settings.json     # Permissions + team agent config
```

## Claude Code Agents

This project is configured for AI-assisted development with [Claude Code](https://code.claude.com).

| Agent | Role | Model | Access |
|-------|------|-------|--------|
| backend | Backend API development | Sonnet | Full |
| frontend | Frontend development | Sonnet | Full |
| devops | Infrastructure & CI/CD | Sonnet | Full |
| devsecops | Security & compliance | Sonnet | Full |
| qa | Testing & quality | Sonnet | Full |
| reviewer | Code review | Haiku | Read-only |
| planner | Architecture & planning | Sonnet | Read-only |

### Skills (Slash Commands)

| Command | Description |
|---------|-------------|
| `/review` | Review code changes for bugs, security, and style |
| `/plan` | Create implementation plan for a feature |
| `/deploy` | Run build, test, and deploy pipeline |
| `/status` | Quick project status report |

### Rules

Contextual rules in `.claude/rules/` are automatically loaded based on which files you're editing:

- **code-quality.md** — Anti-sycophancy, scope guardrails, file size limits, evidence-based claims
- **security.md** — Secrets handling, input validation, auth best practices
- **testing.md** — Test quality standards, coverage expectations, flaky test policy
- **git-workflow.md** — Conventional commits, branch strategy, PR guidelines

## Development

See [docs/guides/](docs/guides/) for development guides.

## License

Private project.
