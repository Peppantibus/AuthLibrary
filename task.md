# AuthLibrary Task Backlog

## Execution Mode

- Execute tasks in strict order from top to bottom.
- Use exactly one commit per completed task.
- Commit message format: `short description`.
- For each task follow: analyze -> implement -> run targeted tests -> commit.
- If a task is blocked, mark it `BLOCKED` in this file with reason, then continue to next task.

## Security Tasks

### SEC-001
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/ExternalLoginService.cs`, `AuthLibrary.Core/Services/RateLimitService.cs`
- Problem: Google replay lock is acquired too early and not released on internal failures.
- Impact: Legitimate retries with same `id_token` can be rejected after transient backend failures.
- Remediation:
  - Ensure replay lock is not consumed permanently on non-security failures.
  - Add controlled lock release or two-phase in-flight/finalized replay strategy.
  - Keep replay rejection deterministic for true replays.
- Status: DONE
- Commit message: `prevent replay lock consumption on transient external login failures`

### SEC-002
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`
- Problem: Resend flow still leaks account state under mail/template/rate-limit internal failures.
- Impact: Residual account enumeration signal in degraded conditions.
- Remediation:
  - Keep uniform external response semantics across all resend outcomes.
  - Apply consistent transition behavior and avoid distinguishable failure outputs.
  - Move details to logs/telemetry only.
- Status: DONE
- Commit message: `enforce uniform resend behavior under internal failures`

### SEC-003
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/PasswordService.cs`
- Problem: Recovery flow returns different outcomes for existing vs non-existing accounts when email dispatch fails.
- Impact: Account existence can be inferred during mail subsystem faults.
- Remediation:
  - Return same generic response in recovery regardless of account existence and internal mail errors.
  - Preserve internal diagnostics without exposing state differences.
- Status: DONE
- Commit message: `normalize recovery response semantics during email failures`

## Reliability & Refactoring Tasks

### REF-001
- Priority: MEDIA
- Area: `AuthLibrary.Tests/Services/RateLimitServiceTests.cs`, `AuthLibrary.Tests/Services/InMemoryCacheServiceTests.cs`
- Problem: Atomic cooldown/replay behavior is tested only in sequential scenarios.
- Impact: Concurrency regressions can slip through unnoticed.
- Remediation:
  - Add concurrent tests for `TryStartCooldown` and `TrySetValue` race scenarios.
  - Assert single winner semantics and deterministic loser behavior.
- Status: DONE
- Commit message: `add concurrency regression tests for atomic cooldown acquisition`

### REF-002
- Priority: MEDIA
- Area: `AuthLibrary.Tests/Services/AuthServiceTests.cs`
- Problem: Missing regression test for external login retry after transient internal failure.
- Impact: Replay policy changes may break legitimate retry behavior silently.
- Remediation:
  - Add test covering first attempt failing after lock acquisition and second attempt behavior.
  - Assert expected policy explicitly (allow retry or reject by design).
- Status: DONE
- Commit message: `add external login retry policy regression coverage`

### REF-003
- Priority: BASSA
- Area: `nuget.config`, `.gitignore`
- Problem: Tracked `nuget.config` can accidentally include credentials.
- Impact: Potential token leakage risk during local edits and commits.
- Remediation:
  - Introduce safe config strategy (`nuget.config.example` + local override) or enforce credential scanning guard.
  - Document recommended local setup for private feeds.
- Status: DONE
- Commit message: `harden nuget configuration workflow against credential leakage`
