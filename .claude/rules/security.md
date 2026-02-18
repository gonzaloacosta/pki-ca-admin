# Security Rules

## Secrets
- **NEVER** commit secrets, tokens, API keys, or credentials.
- Use environment variables or a secrets manager.
- If you find a secret in code, flag it immediately — don't just move it.

## Dependencies
- Pin dependency versions in production.
- Check for known vulnerabilities before adding new dependencies.
- Prefer well-maintained packages with active security response.

## Input Validation
- Validate and sanitize ALL user input.
- Use parameterized queries — never string-concatenate SQL.
- Validate file paths to prevent directory traversal.

## Authentication & Authorization
- Use established auth libraries — don't roll your own crypto.
- Apply least-privilege principle to all service accounts.
- Validate JWT tokens on every request, not just at login.

## Logging
- Never log sensitive data (passwords, tokens, PII).
- Log security-relevant events (auth failures, permission denials).
- Include request IDs for traceability.
