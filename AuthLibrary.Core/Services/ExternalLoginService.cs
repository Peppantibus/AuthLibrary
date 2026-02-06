using System.Security.Cryptography;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class ExternalLoginService<TUser> : IExternalLoginService<TUser> where TUser : class, IAuthUser
{
    private readonly AuthRuntime<TUser> _runtime;

    public ExternalLoginService(AuthRuntime<TUser> runtime)
    {
        _runtime = runtime;
    }

    public async Task<Result<RefreshTokenDto>> ExternalLoginWithGoogle(string idToken, string? expectedNonce = null)
    {
        ExternalUserInfo externalUser;
        try
        {
            externalUser = await _runtime.ExternalTokenValidator.ValidateGoogleIdToken(idToken, expectedNonce);
        }
        catch (InvalidOperationException ex)
        {
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidToken, ex.Message);
        }
        catch
        {
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidToken);
        }

        if (!externalUser.EmailVerified)
        {
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.EmailNotVerified);
        }

        var email = AuthRuntime<TUser>.NormalizeEmail(externalUser.Email);
        if (string.IsNullOrWhiteSpace(email))
        {
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidEmail);
        }

        var replayKey = AuthRuntime<TUser>.HashToken(idToken);
        var replayWindow = BuildReplayWindow(externalUser.ExpiresAtUtc);
        var acquiredReplayLock = await _runtime.RateLimitService.TryStartCooldown(
            RateLimitRequestType.ExternalLogin,
            replayKey,
            replayWindow);
        if (!acquiredReplayLock)
        {
            _runtime.Logger.LogWarning("Google id_token replay rilevato");
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidToken);
        }

        var releaseReplayLock = true;
        try
        {
            var rateLimitResult = await _runtime.RateLimitGuard.EnsureNotBlockedAndRegisterAttempt(
                RateLimitRequestType.ExternalLogin,
                email,
                "utente bloccato",
                "utente bloccato per troppi tentativi");
            if (rateLimitResult.IsFailure)
            {
                _runtime.Logger.LogWarning("Login Google bloccato (rate limit)");
                return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.RateLimited, rateLimitResult.Error);
            }

            const string provider = "google";
            var externalLogin = await _runtime.Repository.GetExternalLoginAsync(provider, externalUser.Subject);

            TUser? user;
            if (externalLogin != null)
            {
                user = await _runtime.Repository.GetUserByIdAsync(externalLogin.UserId);
                if (user == null)
                {
                    return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidUser);
                }
            }
            else
            {
                var existingByEmail = await _runtime.Repository.GetUserByEmailAsync(email);
                if (existingByEmail != null)
                {
                    return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.ExternalAccountExists);
                }

                try
                {
                    user = CreateUserFromExternal(externalUser, email);
                    var login = new ExternalAuthLogin
                    {
                        Provider = provider,
                        Subject = externalUser.Subject,
                        UserId = user.Id,
                        CreatedAt = DateTime.UtcNow
                    };

                    await ExecuteInTransaction(async () =>
                    {
                        await _runtime.Repository.AddUserAsync(user);
                        await _runtime.Repository.AddExternalLoginAsync(login);
                        await _runtime.Repository.SaveChangesAsync();
                    });
                }
                catch (Exception ex)
                {
                    _runtime.Logger.LogError(ex, "Creazione utente esterno fallita");
                    return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.UserCreationFailed);
                }
            }

            if (!user.EmailVerified)
            {
                user.EmailVerified = true;
                await ExecuteInTransaction(async () =>
                {
                    await _runtime.Repository.UpdateUserAsync(user);
                    await _runtime.Repository.SaveChangesAsync();
                });
            }

            var accessToken = _runtime.TokenService.GenerateAccessToken(user);
            var refreshToken = await _runtime.TokenService.CreateRefreshToken(user);
            await _runtime.RateLimitService.Reset(RateLimitRequestType.ExternalLogin, email);
            releaseReplayLock = false;

            return Result.Ok(new RefreshTokenDto
            {
                NewRefreshToken = refreshToken.PlainToken,
                RefreshTokenExpiresAt = refreshToken.ExpiresAt,
                AccessToken = accessToken,
                User = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Name = user.Name,
                    LastName = user.LastName
                }
            });
        }
        finally
        {
            if (releaseReplayLock)
            {
                await _runtime.RateLimitService.ClearCooldown(RateLimitRequestType.ExternalLogin, replayKey);
            }
        }
    }

    private static TimeSpan BuildReplayWindow(DateTime expiresAtUtc)
    {
        var ttl = expiresAtUtc - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            return TimeSpan.FromMinutes(1);
        }

        return ttl < TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1) : ttl;
    }

    private Task ExecuteInTransaction(Func<Task> operation)
    {
        if (_runtime.Repository is ITransactionalAuthRepository<TUser> transactionalRepository)
        {
            return transactionalRepository.ExecuteInTransactionAsync(operation);
        }

        return operation();
    }

    private TUser CreateUserFromExternal(ExternalUserInfo externalUser, string normalizedEmail)
    {
        if (_runtime.ExternalUserFactory == null)
        {
            throw new InvalidOperationException("Registrare IExternalUserFactory<TUser> per creare utenti esterni.");
        }

        var user = _runtime.ExternalUserFactory.CreateFromExternal(externalUser);

        // Keep identity fields server-owned and bound to validated external claims.
        user.Id = Guid.NewGuid().ToString();
        user.Email = normalizedEmail;
        user.Username = normalizedEmail;
        if (string.IsNullOrWhiteSpace(user.Name))
        {
            user.Name = externalUser.GivenName ?? externalUser.Name ?? string.Empty;
        }
        if (string.IsNullOrWhiteSpace(user.LastName))
        {
            user.LastName = externalUser.FamilyName ?? string.Empty;
        }

        user.EmailVerified = true;
        user.PasswordUpdatedAt = null;

        if (string.IsNullOrWhiteSpace(user.Password) || string.IsNullOrWhiteSpace(user.Salt))
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var randomPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var hashedPw = _runtime.HashPassword(randomPassword, salt);
            user.Password = Convert.ToBase64String(hashedPw);
            user.Salt = Convert.ToBase64String(salt);
        }

        return user;
    }
}
