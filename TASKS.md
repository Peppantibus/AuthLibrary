# AuthLibrary Task Backlog

## Execution Mode

- Execute tasks in strict order from top to bottom.
- Use exactly one commit per completed task.
- Commit message format: `SEC-XXX: short description` or `REF-XXX: short description`.
- For each task follow: analyze -> implement -> run targeted tests -> commit.
- If a task is blocked, mark it `BLOCKED` in this file with reason, then continue to next task.

## Security Tasks

### SEC-001
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/RateLimitService.cs`
- Problem: Client IP is taken from `X-Forwarded-For` using `Split(',')[0]` without strong validation.
- Impact: IP spoofing can bypass IP-based rate limiting.
- Remediation:
  - Remove unsafe manual trust of raw forwarded values.
  - Use trusted proxy handling and validated client IP extraction.
  - Keep behavior safe-by-default when proxy config is missing.
- Status: DONE
- Commit message: `SEC-001: harden client IP extraction for rate limiting`

### SEC-002
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/TokenService.cs`, `AuthLibrary.Core/Interfaces/IAuthRepository.cs`
- Problem: Refresh token rotation is not atomic (race window on concurrent refresh).
- Impact: Same refresh token can be rotated more than once under concurrency.
- Remediation:
  - Add atomic rotation method in repository contract.
  - Enforce conditional update with affected rows check.
  - Use transaction/locking strategy in repository implementation guidance.
- Status: DONE
- Commit message: `SEC-002: introduce atomic refresh token rotation contract`

### SEC-003
- Priority: ALTA
- Area: `AuthLibrary.Core/Extensions/ServiceCollectionExtensions.cs`, `AuthLibrary.Core/Configuration/RateLimitSettings.cs`
- Problem: Redis fallback to in-memory is allowed by default.
- Impact: In multi-node deployments, distributed rate limiting can silently degrade.
- Remediation:
  - Enforce production-safe behavior via `RequireRedis=true`.
  - Add startup validation/fail-fast for critical mode.
  - Provide controlled failure strategy for auth endpoints when Redis is required.
- Status: DONE
- Commit message: `SEC-003: enforce safer redis requirement and startup validation`

### SEC-004
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/AuthService.Login.cs`, `AuthLibrary.Core/Services/RateLimitService.cs`
- Problem: User identifier counter is incremented before credential validation.
- Impact: Targeted lockout DoS against known usernames/emails.
- Remediation:
  - Rebalance rate-limit policy to reduce account lockout abuse.
  - Separate abusive-source throttling from hard user lock behavior.
- Status: DONE
- Commit message: `SEC-004: reduce user-lockout dos surface in login rate limiting`

### SEC-005
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/InMemoryCacheService.cs`
- Problem: In-memory lock dictionary can grow with high-cardinality keys.
- Impact: Memory growth and potential service degradation in fallback mode.
- Remediation:
  - Replace per-key lock growth with bounded locking strategy.
  - Add cleanup strategy aligned with cache expiration.
- Status: DONE
- Commit message: `SEC-005: bound in-memory rate-limit lock growth`

### SEC-006
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/GoogleTokenValidator.cs`, `AuthLibrary.Core/Services/AuthService.External.cs`
- Problem: Google ID token validation lacks nonce/session binding and replay protection.
- Impact: Stolen valid ID tokens can be replayed within validity window.
- Remediation:
  - Add nonce validation contract for backend-bound flows.
  - Add replay cache strategy based on token identifiers/claims.
- Status: TODO
- Commit message: `SEC-006: add nonce and replay protections for google login`

### SEC-007
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/AuthService.Email.cs`
- Problem: Response messages in resend verification flow are not fully uniform.
- Impact: Potential account state enumeration.
- Remediation:
  - Return same user-facing message for all resend outcomes.
  - Keep detail only in internal logs.
- Status: TODO
- Commit message: `SEC-007: normalize resend verification responses`

## Refactoring Tasks

### REF-001
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/AuthService*.cs`
- Problem: `AuthService` still contains multiple domain responsibilities.
- Action:
  - Extract domain services (login, registration, password, email, external auth).
  - Inject abstractions through DI.
- Benefit: Better testability, lower coupling, clearer boundaries.
- Status: TODO
- Commit message: `REF-001: split auth service responsibilities into domain services`

### REF-002
- Priority: ALTA
- Area: `AuthLibrary.Core/Services/AuthService*.cs`, `AuthLibrary.Core/Services/TokenService.cs`
- Problem: Multi-step operations have multiple `SaveChangesAsync()` without explicit transaction boundaries.
- Action:
  - Introduce explicit unit-of-work/transaction boundaries for critical flows.
- Benefit: Stronger consistency and safer rollback behavior.
- Status: TODO
- Commit message: `REF-002: add explicit transaction boundaries to critical auth flows`

### REF-003
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/AuthService*.cs`, `AuthLibrary.Core/Services/RateLimitGuard.cs`
- Problem: Rate-limit and cooldown orchestration is repeated.
- Action:
  - Centralize policy orchestration in dedicated reusable component.
- Benefit: Lower duplication and more consistent behavior.
- Status: TODO
- Commit message: `REF-003: centralize rate-limit and cooldown orchestration`

### REF-004
- Priority: MEDIA
- Area: `AuthLibrary.Core/Services/*.cs`, `AuthLibrary.Core/Models/Result.cs`
- Problem: Error handling relies on string literals spread across services.
- Action:
  - Introduce typed error codes and message mapping.
- Benefit: Stable API contracts and better observability/localization.
- Status: TODO
- Commit message: `REF-004: introduce typed error codes for auth flows`

### REF-005
- Priority: MEDIA
- Area: `AuthLibrary.Core/Validation/InputValidators.cs`, `AuthLibrary.Core/Interfaces/IPasswordValidator.cs`
- Problem: Input validation is minimal (mostly non-empty checks).
- Action:
  - Add explicit limits and format checks for key auth inputs.
- Benefit: Better resilience and predictable behavior under malformed input.
- Status: TODO
- Commit message: `REF-005: strengthen input validation limits and formats`

### REF-006
- Priority: MEDIA
- Area: `AuthLibrary.Core/Configuration/*.cs`, `AuthLibrary.Core/Extensions/ServiceCollectionExtensions.cs`
- Problem: Configuration validation is fragmented.
- Action:
  - Add centralized options validation and startup fail-fast checks.
- Benefit: Earlier failure detection and clearer diagnostics.
- Status: TODO
- Commit message: `REF-006: centralize options validation with startup checks`

### REF-007
- Priority: MEDIA
- Area: `AuthLibrary.Tests/Services/*.cs`
- Problem: Missing high-risk scenario tests (concurrency, replay, fallback behavior).
- Action:
  - Add targeted tests for security-critical edge cases and regressions.
- Benefit: Better regression protection on sensitive flows.
- Status: TODO
- Commit message: `REF-007: add security regression tests for critical edge cases`

### REF-008
- Priority: BASSA
- Area: `README.md`, `AuthLibrary.Core/Interfaces/IAuthService.cs`
- Problem: Documentation can drift from implemented features and contracts.
- Action:
  - Align README and examples with actual public API and enabled features.
- Benefit: Better integration reliability and lower onboarding friction.
- Status: TODO
- Commit message: `REF-008: align documentation with current auth api`
