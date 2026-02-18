---
name: deploy
description: Build, test, and deploy the application. Runs the full CI pipeline locally before pushing.
---

# Deploy

Run the full build and deploy pipeline.

## Steps

1. **Verify clean state** — `git status` should show no uncommitted changes
2. **Run tests** — Execute the full test suite
3. **Build** — Run the production build
4. **Docker** — Build container images if applicable
5. **Deploy** — Push to the target environment

## Pre-flight Checklist

Before deploying, verify:
- [ ] All tests pass
- [ ] Build succeeds without warnings
- [ ] No TODO/FIXME in changed files (unless tracked in issues)
- [ ] CHANGELOG updated if releasing a version
- [ ] Environment variables documented

## Rollback Plan

Always know how to rollback. Document:
- Previous working version/tag
- Database migration reversibility
- Feature flags to disable
