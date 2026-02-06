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
- Area: `AuthLibrary.Core/Interfaces/IRateLimitService.cs`, `AuthLibrary.Core/Services/RedisService.cs`, `AuthLibrary.Core/Services/ExternalLoginService.cs`
- Problem: Google login replay guard is not atomic (TOCTOU between cooldown check and set).
- Impact: Concurrent requests with same `id_token` can both pass replay protection.
- Remediation:
  - Introduce atomic replay lock (`SET NX EX`) for Redis implementation.
  - Add equivalent atomic behavior in in-memory fallback.
  - Replace `IsInCooldown`/`StartCooldown` pair with a single atomic acquire API in external login flow.
- Status: DONE
- Commit message: `enforce atomic replay lock for google external login`

### SEC-002
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/RateLimitService.cs`, `AuthLibrary.Core/Configuration/AuthLibraryOptionsValidator.cs`
- Problem: Partial rate-limit configuration can trigger runtime exceptions when required enum rules are missing.
- Impact: Service can crash at runtime instead of safe fallback behavior.
- Remediation:
  - Merge default rate-limit rules with user overrides.
  - Add startup validation to ensure all required `RateLimitRequestType` entries exist.
  - Fail early with clear diagnostics when config is invalid.
- Status: DONE
- Commit message: `harden rate-limit config merge and startup validation`

### SEC-03
- Priority: ALTA
- Area: `AuthLibrary.Core/Extensions/ServiceCollectionExtensions.cs`
- Problem: Redis fail-fast is only partial; startup validation does not eagerly verify real connection.
- Impact: App can start and fail on first auth request in critical Redis-required mode.
- Remediation:
  - Add real eager connection/health-check during bootstrap when Redis is required.
  - Ensure startup fails deterministically if Redis is unavailable.
- Status: DONE
- Commit message: `make redis startup fail-fast eager and deterministic`

### SEC-004
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`
- Problem: Resend verification flow is still distinguishable for already-verified accounts (rate-limit/cooldown transitions differ).
- Impact: Residual account-state enumeration signal.
- Remediation:
  - Apply same anti-enumeration transitions for already-verified users.
  - Keep user-facing response semantics uniform across outcomes.
- Status: TODO
- Commit message: `normalize resend rate-limit transitions for anti-enumeration`

### SEC-005
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/RegisterService.cs`, `AuthLibrary.Core/Validation/InputValidators.cs`
- Problem: Registration flow does not apply new `ValidateEmail`/`ValidateUsername` checks before expensive operations.
- Impact: Malformed input can reach rate-limit and repository paths with inconsistent errors.
- Remediation:
  - Validate email and username in `AddUser` before rate-limit/repository calls.
  - Add null checks on `user` and return typed failures consistently.
- Status: TODO
- Commit message: `enforce registration input hardening before persistence`

## Reliability & Refactoring Tasks

### REF-001
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Tests/Services/AuthServiceTests.cs`
- Problem: `VerifyMail` can return success (`true`) when token is valid but user no longer exists.
- Impact: Incorrect verification outcome and stale-token behavior.
- Remediation:
  - If `user == null`, invalidate token and return `Result.Ok(false)` or typed `InvalidUser`.
  - Add dedicated regression test coverage.
- Status: TODO
- Commit message: `fix verifymail behavior for missing user and add tests`

### REF-002
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Core/Services/PasswordService.cs`
- Problem: Email send failures in resend/recovery paths can propagate exceptions.
- Impact: Unhandled failures and inconsistent error contracts.
- Remediation:
  - Add robust exception handling around email dispatch in resend/recovery flows.
  - Return typed failures with stable error code semantics.
- Status: TODO
- Commit message: `harden email send error handling in resend and recovery`

### REF-003
- Priority: MEDIA
- Area: `README.md`, `AuthLibrary.Core/Services/RegisterService.cs`, `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Core/Services/PasswordService.cs`
- Problem: Documentation claims stable `ErrorCode` for all failures, but some flows still use untyped `Result.Fail(...)`.
- Impact: Regressive public contract and integration ambiguity.
- Remediation:
  - Align implementation to typed errors across remaining flows or adjust README contract explicitly.
  - Ensure docs and runtime behavior match.
- Status: TODO
- Commit message: `align errorcode contract across docs and service failures`

### REF-004
- Priority: MEDIA
- Area: `nuget.config`
- Problem: Dependency audit is blocked by private feed resolution/auth issue (`NU1301`).
- Impact: Vulnerability scan is unreliable and cannot be used as release gate.
- Remediation:
  - Fix feed mapping/authentication for private source used in restore/audit.
  - Ensure `dotnet restore` and vulnerability scan run consistently in CI/local.
- Status: TODO
- Commit message: `restore reliable dependency audit by fixing private feed configuration`
