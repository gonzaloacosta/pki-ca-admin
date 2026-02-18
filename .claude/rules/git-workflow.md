# Git Workflow

## Commits
- Use **conventional commits**: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`
- Keep commits atomic — one logical change per commit.
- Write meaningful commit messages that explain **why**, not just what.

## Branches
- `main` — production-ready code, always deployable.
- `feat/<name>` — new features.
- `fix/<name>` — bug fixes.
- `chore/<name>` — maintenance, dependencies, CI.

## Pull Requests
- One concern per PR. Don't bundle unrelated changes.
- Include a description of what and why.
- Reference related issues.
- Ensure CI passes before requesting review.

## Pre-Commit Checklist
Before committing, verify:
1. Code compiles / builds without errors.
2. All tests pass.
3. Linter passes with no new warnings.
4. No secrets or credentials in the diff.
5. No unrelated changes included.
