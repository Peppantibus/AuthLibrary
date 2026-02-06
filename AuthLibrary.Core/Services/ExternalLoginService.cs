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
            return Result.Fail<RefreshTokenDto>(ex.Message);
        }
        catch
        {
            return Result.Fail<RefreshTokenDto>("token non valido");
        }

        if (!externalUser.EmailVerified)
        {
            return Result.Fail<RefreshTokenDto>("email non verificata");
        }

        var email = AuthRuntime<TUser>.NormalizeEmail(externalUser.Email);
        if (string.IsNullOrWhiteSpace(email))
        {
            return Result.Fail<RefreshTokenDto>("email non valida");
        }

        var replayKey = AuthRuntime<TUser>.HashToken(idToken);
        if (await _runtime.RateLimitService.IsInCooldown(RateLimitRequestType.ExternalLogin, replayKey))
        {
            _runtime.Logger.LogWarning("Google id_token replay rilevato");
            return Result.Fail<RefreshTokenDto>("token non valido");
        }

        var rateLimitResult = await _runtime.RateLimitGuard.EnsureNotBlockedAndRegisterAttempt(
            RateLimitRequestType.Login,
            email,
            "utente bloccato",
            "utente bloccato per troppi tentativi");
        if (rateLimitResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Login Google bloccato (rate limit)");
            return Result.Fail<RefreshTokenDto>(rateLimitResult.Error);
        }

        const string provider = "google";
        var externalLogin = await _runtime.Repository.GetExternalLoginAsync(provider, externalUser.Subject);

        TUser? user;
        if (externalLogin != null)
        {
            user = await _runtime.Repository.GetUserByIdAsync(externalLogin.UserId);
            if (user == null)
            {
                return Result.Fail<RefreshTokenDto>("utente non valido");
            }
        }
        else
        {
            var existingByEmail = await _runtime.Repository.GetUserByEmailAsync(email);
            if (existingByEmail != null)
            {
                return Result.Fail<RefreshTokenDto>("account già esistente, collega google");
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
                return Result.Fail<RefreshTokenDto>("impossibile creare utente");
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
        await _runtime.RateLimitService.Reset(RateLimitRequestType.Login, email);
        await _runtime.RateLimitService.StartCooldown(
            RateLimitRequestType.ExternalLogin,
            replayKey,
            BuildReplayWindow(externalUser.ExpiresAtUtc));

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

    private static TimeSpan BuildReplayWindow(DateTime expiresAtUtc)
    {
        var ttl = expiresAtUtc - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            return TimeSpan.FromMinutes(1);
        }

        // Keep a minimum floor to avoid edge cases with clock skew.
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

        if (string.IsNullOrWhiteSpace(user.Id))
        {
            user.Id = Guid.NewGuid().ToString();
        }
        if (string.IsNullOrWhiteSpace(user.Email))
        {
            user.Email = normalizedEmail;
        }
        if (string.IsNullOrWhiteSpace(user.Username))
        {
            user.Username = normalizedEmail;
        }
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
