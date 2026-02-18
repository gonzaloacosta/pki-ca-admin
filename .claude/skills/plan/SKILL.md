---
name: plan
description: Create a detailed implementation plan for a feature or task. Analyzes the codebase, identifies dependencies, and breaks work into phases.
---

# Implementation Planning

Create a detailed implementation plan for the requested feature or task.

## Steps

1. **Understand** — Read CLAUDE.md and relevant docs to understand the project context
2. **Explore** — Scan the codebase to understand existing patterns, dependencies, and architecture
3. **Design** — Propose the technical approach with trade-offs considered
4. **Break down** — Split into phases with clear deliverables
5. **Assign** — Suggest which agents (backend, frontend, devops, etc.) should handle each phase

## Output

Save the plan to `docs/architecture/plan-<feature-name>.md` with:

- **Goal**: What we're building and why
- **Approach**: Technical design with alternatives considered
- **Phases**: Ordered list with estimated complexity (S/M/L/XL)
- **Dependencies**: What must be done first
- **Risks**: What could go wrong
- **Agent assignments**: Which sub-agent handles each phase
- **Definition of done**: How we know it's complete
