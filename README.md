# AuthLibrary.Core

Lightweight authentication library for .NET (`net9.0`) with JWT access tokens,
refresh token rotation, email verification/password reset flows, and rate limiting.

This package gives you auth business logic and contracts.
You still own HTTP endpoints, persistence implementation, and deployment hardening.

## What You Get

- Credential login with rate limiting
- Registration with password hashing (Argon2 + pepper + per-user salt)
- Email verification flow
- Password recovery and reset flow
- Refresh token rotation with reuse detection
- Optional Google ID token login with nonce and replay protection
- Redis-backed rate limiting with optional in-memory fallback
- Startup configuration validation (fail-fast)

## What This Library Does Not Do

- It does not create controllers/endpoints for you
- It does not configure ASP.NET authorization policies
- It does not replace your DB constraints or transactions
- It does not configure CORS/CSRF/security headers in your host app

## Installation

```bash
dotnet add package AuthLibrary.Core
```

Or use a project reference during local development.

## Quick Start

### 1) Add configuration

```json
{
  "JwtSettings": {
    "Key": "replace-with-a-strong-secret-at-least-32-bytes",
    "Issuer": "MyIssuer",
    "Audience": "MyAudience",
    "AccessTokenLifetimeMinutes": 15
  },
  "SecuritySettings": {
    "Pepper": "replace-with-a-server-secret"
  },
  "MailService": {
    "AppMail": "noreply@example.com",
    "Host": "smtp.example.com",
    "Port": 587,
    "SenderName": "My App",
    "Username": "smtp-user",
    "Password": "smtp-pass",
    "UseSsl": true,
    "TimeoutSeconds": 30,
    "RetryCount": 1,
    "RetryDelayMilliseconds": 500
  },
  "AuthSettings": {
    "FrontendUrl": "https://app.example.com"
  },
  "TemplateSettings": {
    "BasePath": "templates"
  },
  "RefreshTokenSettings": {
    "RefreshTokenLifetimeDays": 30
  },
  "RateLimit": {
    "Rules": {
      "Login": {
        "MaxUserAttempts": 5,
        "MaxIpAttempts": 20,
        "AttemptWindow": "00:15:00",
        "LockDuration": "00:05:00"
      },
      "Register": {
        "MaxUserAttempts": 3,
        "MaxIpAttempts": 10,
        "AttemptWindow": "00:30:00",
        "LockDuration": "00:10:00"
      },
      "VerifyEmail": {
        "MaxUserAttempts": 5,
        "MaxIpAttempts": 15,
        "AttemptWindow": "01:00:00",
        "LockDuration": "00:15:00"
      },
      "ResetPassword": {
        "MaxUserAttempts": 3,
        "MaxIpAttempts": 10,
        "AttemptWindow": "00:30:00",
        "LockDuration": "00:15:00"
      },
      "ExternalLogin": {
        "MaxUserAttempts": 5,
        "MaxIpAttempts": 20,
        "AttemptWindow": "00:15:00",
        "LockDuration": "00:05:00"
      }
    },
    "TrustedProxyIps": ["10.0.0.1", "10.0.0.2"],
    "RequireRedis": true
  },
  "GoogleAuth": {
    "ClientId": "YOUR_GOOGLE_CLIENT_ID",
    "AllowedHostedDomain": "mycompany.com"
  },
  "Redis": {
    "Url": "localhost:6379"
  }
}
```

### 2) Register services

```csharp
services.AddAuthLibrary<MyUser>(configuration);
```

`AddAuthLibrary` now also registers `IHttpContextAccessor` automatically.

### 3) Implement repository contracts

You must implement:

- `IAuthRepository<TUser>`
- Optionally `ITransactionalAuthRepository<TUser>` (strongly recommended)

For Google login user provisioning, also implement:

- `IExternalUserFactory<TUser>`

### 4) Add email templates

Place templates under `TemplateSettings:BasePath`:

- `VerifyEmail.html`
- `ResetPassword.html`

Supported placeholders:

- `{{username}}`
- `{{url}}`

Template values are HTML encoded by the library.

## Security-Critical Integration Requirements

These are mandatory in production:

1. Enforce DB unique constraints on `Username` and `Email`.
2. Keep refresh token rotation atomic in `TryRotateRefreshTokenAsync`.
3. Wrap multi-step updates in DB transactions (`ITransactionalAuthRepository<TUser>`).
4. Keep secrets in secure secret storage, never in source control.
5. Set `RateLimit:RequireRedis=true` for distributed deployments.
6. Configure trusted proxies (`RateLimit:TrustedProxyIps`) correctly.
7. Treat all public user identifiers from clients as untrusted.

## Main Contracts

### `IAuthUser`

Your user model must include:

- `Id`, `Username`, `Email`
- `Password`, `Salt`
- `EmailVerified`
- `PasswordUpdatedAt`
- `Name`, `LastName`

### `IAuthService<TUser>`

Primary entry points:

- `Login`
- `AddUser`
- `RecoveryPassword`
- `ResetPasswordRedirect`
- `ResetPassword`
- `VerifyMail`
- `ResendVerificationEmail`
- `ExternalLoginWithGoogle`

### `ITokenService<TUser>`

Token operations:

- `GenerateAccessToken`
- `CreateRefreshToken`
- `RefreshToken` / `TryRefreshToken`

## Behavior by Flow

### Registration

- Validates email/username/password
- Normalizes email (trim + lower)
- Always generates a server-owned `user.Id`
- Hashes password with Argon2 using `password + pepper`
- Stores only hashed tokens for verify/reset/refresh

### Login

- Input validation before repository lookup
- Pre-auth throttling is IP scoped
- Requires verified email
- Uses constant-time compare for password hash
- On success, resets only user-scoped login counters (not IP counters)

### Refresh Token

- Validates token format and length
- Uses hashed token lookup
- Rotates token via `TryRotateRefreshTokenAsync`
- If reuse is detected, invalidates all sessions for that user
- Invalidates tokens created before `PasswordUpdatedAt`

### Email verification and password recovery

- `RecoveryPassword` is enumeration-safe and always returns generic success text
- `ResendVerificationEmail` is enumeration-safe and returns generic success behavior
- Expired tokens are cleaned up

### Google login

- Validates issuer, audience, lifetime, signature
- Optional nonce check (`expectedNonce`)
- Optional hosted domain restriction (`AllowedHostedDomain`)
- Replay cooldown keyed by hash of the incoming `id_token`

## Result and Error Contract

All methods return `Result` / `Result<T>`:

- `IsSuccess` / `IsFailure`
- `Error` message on failure
- `ErrorCode` stable code string (when provided)

Typical `AuthErrorCode` values:

- `InvalidCredentials`
- `UserBlocked`
- `RateLimited`
- `InvalidToken`
- `TokenRefreshError`
- `EmailNotVerified`
- `RegistrationInvalid`
- `RecoveryError`

## Configuration Validation Rules

Startup fails fast when configuration is invalid.

### `JwtSettings`

- `Key`: required, minimum 32 bytes
- `Issuer`: required
- `Audience`: required
- `AccessTokenLifetimeMinutes`: `1..60`

### `SecuritySettings`

- `Pepper`: required

### `RefreshTokenSettings`

- `RefreshTokenLifetimeDays`: `1..90`

### `AuthSettings`

- `FrontendUrl`: absolute URL
- Must be HTTPS, except local loopback HTTP

### `TemplateSettings`

- `BasePath`: required

### `RateLimit`

- Rules must exist for all request types
- Thresholds/windows must be positive
- `TrustedProxyIps` must contain valid IPs when set

## Default Rate Limit Rules

| Type          | MaxUserAttempts | MaxIpAttempts | AttemptWindow | LockDuration |
|---------------|------------------|----------------|---------------|--------------|
| Login         | 5                | 20             | 15m           | 5m           |
| Register      | 3                | 10             | 30m           | 10m          |
| VerifyEmail   | 5                | 15             | 60m           | 15m          |
| ResetPassword | 3                | 10             | 30m           | 15m          |
| ExternalLogin | 5                | 20             | 15m           | 5m           |

## Minimal API Example

```csharp
app.MapPost("/api/auth/login", async (LoginDto body, IAuthService<MyUser> auth) =>
{
    var result = await auth.Login(body.Username, body.Password);
    if (result.IsFailure) return Results.BadRequest(new { result.Error, result.ErrorCode });
    return Results.Ok(result.Value);
});

app.MapPost("/api/auth/refresh", async (RefreshDto body, ITokenService<MyUser> tokens) =>
{
    var result = await tokens.TryRefreshToken(body.RefreshToken);
    if (result.IsFailure) return Results.Unauthorized();
    return Results.Ok(result.Value);
});

public sealed record LoginDto(string Username, string Password);
public sealed record RefreshDto(string RefreshToken);
```

## Production Checklist

Before shipping:

1. Repository implementation reviewed for transaction and uniqueness guarantees.
2. Refresh token rotation tested under concurrency.
3. Redis mandatory in production and monitored.
4. Secrets rotated and loaded from secure provider.
5. Logging policy reviewed to avoid sensitive data exposure.
6. Host app has strict CORS/AuthZ/headers and CSRF strategy (if cookie-based).
7. Integration tests cover login/register/recovery/refresh edge cases.

## Testing

```bash
dotnet test
```

## Notes on Package Reproducibility

The projects are configured with lock files (`RestorePackagesWithLockFile=true`).
Commit `packages.lock.json` for deterministic restores in CI.
