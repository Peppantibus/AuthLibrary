AuthLibrary
============

Lightweight authentication library for .NET with refresh token rotation,
rate limiting, and email-based flows. Designed to be simpler than full
frameworks while keeping sensible security defaults.

Features
--------
- Login with rate limiting
- Refresh token rotation with reuse detection
- Email verification and password reset flows
- Redis-backed rate limiting with in-memory fallback
- Configurable JWT settings

Quick start
-----------
1) Add configuration (appsettings.json):

```json
{
  "JwtSettings": {
    "Key": "this-is-a-very-long-secret-key-at-least-32-bytes",
    "Issuer": "MyIssuer",
    "Audience": "MyAudience",
    "AccessTokenLifetimeMinutes": 15
  },
  "SecuritySettings": {
    "Pepper": "my-app-secret-pepper"
  },
  "MailService": {
    "AppMail": "noreply@example.com",
    "Host": "smtp.example.com",
    "Port": 587,
    "SenderName": "My App",
    "Username": "smtp-user",
    "Password": "smtp-pass",
    "UseSsl": true
  },
  "AuthSettings": {
    "FrontendUrl": "https://app.example.com"
  },
  "TemplateSettings": {
    "BasePath": "templates"
  },
  "Redis": {
    "Url": "localhost:6379"
  }
}
```

2) Register services:

```csharp
services.AddAuthLibrary<MyUser>(configuration);

// If you need trusted proxies for rate limiting:
services.AddScoped<IRateLimitService>(sp =>
{
    var redis = sp.GetRequiredService<IRedisService>();
    var http = sp.GetRequiredService<IHttpContextAccessor>();
    return new RateLimitService(
        redis,
        http,
        trustedProxyIps: new[] { "10.0.0.1", "10.0.0.2" });
});
```

3) Implement IAuthRepository<TUser> (see below).

Repository contract (required)
------------------------------
You must implement IAuthRepository<TUser> for your storage backend. The
interface includes methods to:
- Store/retrieve users
- Store/retrieve/remove email verification tokens
- Store/retrieve/remove password reset tokens
- Store/rotate refresh tokens

Example skeleton (EF Core style)
--------------------------------
```csharp
public sealed class AuthRepository : IAuthRepository<MyUser>
{
    private readonly AuthDbContext _db;

    public AuthRepository(AuthDbContext db) { _db = db; }

    public Task<MyUser?> GetUserByUsernameAsync(string username) =>
        _db.Users.FirstOrDefaultAsync(u => u.Username == username);

    public Task<MyUser?> GetUserByEmailAsync(string email) =>
        _db.Users.FirstOrDefaultAsync(u => u.Email == email);

    public Task<MyUser?> GetUserByIdAsync(string id) =>
        _db.Users.FirstOrDefaultAsync(u => u.Id == id);

    public Task<bool> UserExistsAsync(string username, string email) =>
        _db.Users.AnyAsync(u => u.Username == username || u.Email == email);

    public Task AddUserAsync(MyUser user) { _db.Users.Add(user); return Task.CompletedTask; }
    public Task UpdateUserAsync(MyUser user) { _db.Users.Update(user); return Task.CompletedTask; }
    public Task RemoveUserAsync(MyUser user) { _db.Users.Remove(user); return Task.CompletedTask; }

    public Task AddEmailVerifiedTokenAsync(EmailVerifiedToken token)
    { _db.EmailVerifiedTokens.Add(token); return Task.CompletedTask; }

    public Task<EmailVerifiedToken?> GetEmailVerifiedTokenAsync(string tokenHash) =>
        _db.EmailVerifiedTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

    public Task RemoveEmailVerifiedTokenAsync(EmailVerifiedToken token)
    { _db.EmailVerifiedTokens.Remove(token); return Task.CompletedTask; }

    public Task RemoveEmailVerifiedTokensByUserIdAsync(string userId)
    {
        _db.EmailVerifiedTokens.RemoveRange(_db.EmailVerifiedTokens.Where(t => t.UserId == userId));
        return Task.CompletedTask;
    }

    public Task AddPasswordResetTokenAsync(PasswordResetToken token)
    { _db.PasswordResetTokens.Add(token); return Task.CompletedTask; }

    public Task<PasswordResetToken?> GetPasswordResetTokenAsync(string tokenHash) =>
        _db.PasswordResetTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

    public Task RemovePasswordResetTokenAsync(PasswordResetToken token)
    { _db.PasswordResetTokens.Remove(token); return Task.CompletedTask; }

    public Task RemovePasswordResetTokensByUserIdAsync(string userId)
    {
        _db.PasswordResetTokens.RemoveRange(_db.PasswordResetTokens.Where(t => t.UserId == userId));
        return Task.CompletedTask;
    }

    public Task AddRefreshTokenAsync(RefreshToken token)
    { _db.RefreshTokens.Add(token); return Task.CompletedTask; }

    public Task<RefreshToken?> GetRefreshTokenAsync(string tokenHash) =>
        _db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

    public Task UpdateRefreshTokenAsync(RefreshToken token)
    { _db.RefreshTokens.Update(token); return Task.CompletedTask; }

    public Task RemoveRefreshTokensByUserIdAsync(string userId)
    {
        _db.RefreshTokens.RemoveRange(_db.RefreshTokens.Where(t => t.UserId == userId));
        return Task.CompletedTask;
    }

    public Task SaveChangesAsync() => _db.SaveChangesAsync();
}
```

Security notes
--------------
- JWT key must be at least 32 bytes.
- Refresh tokens are stored as SHA256 hashes; only the plain token is returned.
- Refresh token reuse invalidates all sessions for that user.
- Rate limiting uses Redis when available; in-memory fallback is best-effort.
- X-Forwarded-For is honored only for trusted proxies (configure explicitly).

Testing
-------
```bash
dotnet test
```
