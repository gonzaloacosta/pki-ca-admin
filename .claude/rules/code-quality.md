# Code Quality Standards

## File Size
- Split files at **300 lines**. If a file exceeds this, refactor into smaller modules.
- If you must exceed 300 lines, explain why in the PR description.

## Anti-Sycophancy
- **If you think the user's approach is wrong, say so.** Don't agree just to be agreeable.
- Provide evidence for your claims. Never say "this code exists" without showing it.
- If you're uncertain, say "I'm not sure" rather than guessing.

## Scope Guardrails
- **Fix only what was asked.** Don't refactor adjacent files unless explicitly requested.
- If you notice something else that should be fixed, mention it — don't fix it silently.
- One PR = one concern. Don't bundle unrelated changes.

## Fix Attempts
- After **2 failed fix attempts**, stop and explain what's happening.
- Don't keep trying variations — escalate to the user with what you've learned.

## Evidence-Based Claims
- Never claim code exists without showing the file path and line.
- Never claim a test passes without running it.
- Never claim a build succeeds without running it.

## Code Style
- Follow existing patterns in the codebase — consistency beats "better".
- If no pattern exists, follow the language's official style guide.
- Comments explain **why**, not **what**. The code explains what.
