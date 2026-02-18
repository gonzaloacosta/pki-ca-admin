---
paths:
  - "**/*.test.*"
  - "**/*.spec.*"
  - "**/tests/**"
  - "**/__tests__/**"
---

# Testing Standards

## Test Quality
- Test **behavior**, not implementation details.
- Each test should have a clear, descriptive name that reads like a sentence.
- One assertion per test when practical — multiple assertions are OK if they test the same behavior.

## Coverage
- All new code must have tests.
- All bug fixes must include a regression test.
- Aim for meaningful coverage, not 100% line coverage.

## Test Structure
- **Arrange → Act → Assert** pattern.
- Use factories/fixtures for test data — don't hardcode values.
- Keep tests independent — no shared mutable state between tests.

## Test Speed
- Unit tests must be fast (< 100ms each).
- Mock external services in unit tests.
- Integration tests can be slower but should still be deterministic.

## Flaky Tests
- Flaky tests must be fixed or deleted immediately.
- Never skip a flaky test and move on — it will rot.
- Use retries only as a temporary measure while investigating.
