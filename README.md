# {{PROJECT_NAME}}

> {{PROJECT_DESCRIPTION}}

## Quick Start

```bash
# TODO: Add setup instructions
```

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
