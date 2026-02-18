---
name: status
description: Check the current project status — git state, recent commits, open TODOs, and test results.
---

# Project Status

Provide a quick status report for the project.

## Checks

1. `git status` — working tree state
2. `git log --oneline -10` — recent commits
3. `grep -rn "TODO\|FIXME\|HACK\|XXX" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" --include="*.go" services/ infra/ scripts/` — open items
4. Run test suite if a test command is configured
5. Check for outdated dependencies if applicable

## Output

Summarize concisely:
- **Branch**: current branch name
- **Last commit**: date + message
- **Working tree**: clean / X files modified
- **Open TODOs**: count by category
- **Tests**: pass/fail count
- **Next steps**: what should be done next based on context
