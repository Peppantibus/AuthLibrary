# AuthLibrary Task Backlog

## Execution Mode

- Execute tasks in strict order from top to bottom.
- Use exactly one commit per completed task.
- Commit message format: `short description`.
- For each task follow: analyze -> implement -> run targeted tests -> commit.
- If a task is blocked, mark it `BLOCKED` in this file with reason, then continue to next task.
- When all tasks are marked `DONE`, remove `task.md` from the repository and push the deletion to GitHub.

## Security Tasks

### SEC-001
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/LoginService.cs`
- Problem: Login flow has timing asymmetry between existing and non-existing users due to Argon2 execution only on existing accounts.
- Impact: Remote attacker can infer valid usernames via latency profiling and run targeted brute-force/phishing.
- Remediation:
  - Add a constant-time fallback hash path when user is missing.
  - Keep response semantics and timing envelope uniform for missing user, wrong password, and unverified email.
  - Add regression tests for coarse latency parity between negative cases.
- Status: DONE
- Commit message: `harden login against timing-based user enumeration`

### SEC-002
- Priority: ALTA
- Area: `AuthLibrary.Core/Configuration/AuthLibraryOptionsValidator.cs`, `AuthLibrary.Core/Services/EmailVerificationService.cs`
- Problem: `AuthSettings:FrontendUrl` accepts `http://`, while reset/verify links embed bearer-style tokens.
- Impact: Tokens can be intercepted on non-TLS transport, enabling account takeover via password reset or email verification links.
- Remediation:
  - Enforce HTTPS at startup validation (optionally allow loopback for local development only).
  - Add tests that reject non-HTTPS production URLs.
  - Update README configuration examples to emphasize HTTPS-only behavior.
- Status: DONE
- Commit message: `enforce https-only frontend urls for auth token links`

### SEC-003
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/PasswordService.cs`, `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Core/Services/RateLimitService.cs`
- Problem: Recovery/resend flows use user-provided email directly as rate-limit identifier without strict pre-validation and length bounds.
- Impact: High-cardinality/malformed identifiers can inflate Redis/memory keyspace and degrade service availability.
- Remediation:
  - Validate email format and length before rate-limit operations.
  - Add a defensive max-length cap for generic identifiers in rate-limit key composition.
  - Preserve enumeration-safe generic responses for invalid or unknown emails.
- Status: DONE
- Commit message: `validate and bound rate-limit identifiers for email flows`

### SEC-004
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Core/Services/PasswordService.cs`, `AuthLibrary.Core/Services/RegisterService.cs`
- Problem: Warning/Error logs include raw email values at production log levels.
- Impact: PII can leak into centralized logs and retention systems, increasing compliance and privacy risk.
- Remediation:
  - Remove or mask email/user identifiers from Warning/Error logs.
  - Keep raw identifiers only in Debug-level logs.
  - Add targeted tests/assertions for log templates where feasible.
- Status: DONE
- Commit message: `reduce pii exposure in warning and error logs`

### SEC-005
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/ExternalLoginService.cs`
- Problem: External Google login throttling uses `RateLimitRequestType.Login` instead of dedicated `ExternalLogin` policy for account-level counters/reset.
- Impact: `ExternalLogin` policy can be bypassed or misapplied when configured differently from `Login`.
- Remediation:
  - Use `RateLimitRequestType.ExternalLogin` for gate/register/reset in external login flow.
  - Keep replay cooldown logic separate from account policy counters.
  - Add regression tests proving policy separation between login methods.
- Status: DONE
- Commit message: `apply dedicated external login rate-limit policy`

### SEC-006
- Priority: MEDIA
- Area: `AuthLibrary.Core/AuthLibrary.Core.csproj`
- Problem: Dependency graph includes legacy ASP.NET Core 2.3.x HTTP abstractions/features on a `net9.0` library.
- Impact: Unsupported dependency line increases long-term security and maintenance risk.
- Remediation:
  - Replace legacy HTTP abstractions with supported versions aligned with target framework.
  - Regenerate assets/lock and verify no transitive downgrade remains.
  - Run full auth/security regression suite after package upgrade.
- Status: DONE
- Commit message: `upgrade legacy aspnetcore http dependencies`

### SEC-007
- Priority: BASSA
- Area: `AuthLibrary.Core/Services/EmailVerificationService.cs`, `AuthLibrary.Core/Services/PasswordService.cs`
- Problem: `VerifyMail` and `ResetPasswordRedirect` hash/process raw token input without fast pre-validation.
- Impact: Malformed input can create unnecessary processing and DB queries.
- Remediation:
  - Add lightweight token length/charset checks before hashing and repository lookup.
  - Return uniform negative outcome for malformed token input.
  - Add tests for malformed token rejection path.
- Status: DONE
- Commit message: `prevalidate tokens in verify and redirect flows`

### SEC-008
- Priority: BASSA
- Area: `AuthLibrary.Core/Interfaces/IAuthUser.cs`, `AuthLibrary.Core/Services/RegisterService.cs`
- Problem: User ID handling depends on caller-provided entity and host integration behavior.
- Impact: In insecure host mappings, predictable or client-controlled IDs can cause logical abuse/collisions.
- Remediation:
  - Enforce server-side user ID assignment in registration when missing/invalid.
  - Document mandatory unique constraints and safe mapping rules for host repositories.
  - Add integration tests/guidance for secure ID handling.
- Status: DONE
- Commit message: `harden user id handling in registration contracts`

## Reliability & Refactoring Tasks

### REF-001
- Priority: MEDIA
- Area: `AuthLibrary.Tests/Services/AuthServiceTests.cs`, `AuthLibrary.Tests/Services/LoginServiceTests.cs`
- Problem: Missing dedicated regression coverage for timing-safe negative login paths.
- Impact: Future changes can silently reintroduce enumeration side-channel.
- Remediation:
  - Add tests that compare execution envelopes for invalid-user vs invalid-password scenarios.
  - Keep assertions stable using coarse timing thresholds and repeated sampling.
- Status: DONE
- Commit message: `add regression tests for timing-safe login failures`

### REF-002
- Priority: MEDIA
- Area: `README.md`, `AuthLibrary.Core/Interfaces/IAuthRepository.cs`
- Problem: Security-critical host integration constraints are only partially documented.
- Impact: Consumers can implement repository/identity flows in insecure ways.
- Remediation:
  - Add explicit guidance for unique indexes, transactional boundaries, and server-side ID ownership.
  - Document logging privacy expectations and HTTPS requirement for frontend auth URLs.
- Status: DONE
- Commit message: `document security-critical integration constraints for consumers`
