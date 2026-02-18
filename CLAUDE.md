# CLAUDE.md — {{PROJECT_NAME}}

## Project Overview

{{PROJECT_DESCRIPTION}}

See @README for project overview.

## Architecture

See @docs/architecture/ for design documents and ADRs.

```
TODO: Add architecture diagram
```

## Monorepo Structure

```
├── services/
│   ├── backend/        # Backend API / business logic
│   └── frontend/       # Frontend application
├── infra/
│   ├── terraform/      # Infrastructure as Code
│   ├── kubernetes/     # K8s manifests / Helm charts
│   └── docker/         # Dockerfiles and compose files
├── docs/
│   ├── architecture/   # ADRs and system design
│   ├── guides/         # How-to guides and runbooks
│   ├── images/         # Diagrams and screenshots
│   └── trash/          # Archived/deprecated docs
├── scripts/            # Dev scripts, automation
└── .claude/
    ├── agents/         # Sub-agents (backend, frontend, devops, devsecops, qa, reviewer, planner)
    ├── rules/          # Contextual rules (code-quality, security, testing, git-workflow)
    ├── skills/         # Slash commands (/review, /plan, /deploy, /status)
    └── settings.json   # Permissions, env vars, team agents
```

## Agent Behavior Rules

### Think Before You Act
- Read existing code before making changes.
- Check `docs/architecture/` for prior decisions.
- Follow existing patterns — consistency beats "better".

### Be Honest
- If my approach is wrong, **tell me**. Don't agree just to be agreeable.
- If you're uncertain, say "I'm not sure" — don't guess.
- Never claim code exists without showing the file path and line.
- Never claim tests pass without running them.

### Stay Focused
- Fix only what was asked. Don't refactor adjacent files unless requested.
- If you notice other issues, mention them — don't fix them silently.
- After 2 failed fix attempts, **stop and explain** what you've learned.

### Quality Gates
- Run tests before and after changes.
- Run the linter before committing.
- Keep files under 300 lines — refactor if they grow larger.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | TODO |
| **Frontend** | TODO |
| **Database** | TODO |
| **Infrastructure** | TODO |
| **CI/CD** | GitHub Actions |

## Commands

```bash
# Setup
TODO

# Run locally
TODO

# Test
TODO

# Deploy
TODO
```

## Agents

| Agent | Role | Model | Tools |
|-------|------|-------|-------|
| backend | Backend development | sonnet | Full |
| frontend | Frontend development | sonnet | Full |
| devops | Infrastructure & CI/CD | sonnet | Full |
| devsecops | Security & compliance | sonnet | Full |
| qa | Testing & quality | sonnet | Full |
| reviewer | Code review (read-only) | haiku | Read, Glob, Grep |
| planner | Architecture & planning (read-only) | sonnet | Read, Glob, Grep |

## Important Notes

- Git author: Gonzalo Acosta <gonzaloacostapeiro@gmail.com>
- All repos live in `~/github/`
- Notion project page: TODO
