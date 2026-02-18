---
name: review
description: Review code changes for bugs, security issues, and style violations. Runs git diff and analyzes changed files.
---

# Code Review

Review the latest code changes thoroughly.

## Steps

1. Run `git diff HEAD~1` (or `git diff --staged` if there are staged changes)
2. Read each changed file completely
3. Analyze for:
   - **Bugs**: Logic errors, off-by-one, null references, race conditions
   - **Security**: Injection, auth bypass, secrets exposure, input validation
   - **Performance**: N+1 queries, unnecessary allocations, missing indexes
   - **Style**: Inconsistency with existing code, naming conventions
   - **Tests**: Missing test coverage for new/changed behavior

## Output Format

Group findings by severity:

### 🔴 Critical (must fix)
- Security vulnerabilities
- Data loss risks
- Breaking changes

### 🟡 Warning (should fix)
- Bug risks
- Performance issues
- Missing error handling

### 🟢 Suggestions (nice to have)
- Style improvements
- Readability enhancements
- Documentation gaps

If no issues found, say so explicitly — don't invent problems.
