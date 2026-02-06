using System.Security.Cryptography;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using AuthLibrary.Validation;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class LoginService<TUser> : ILoginService<TUser> where TUser : class, IAuthUser
{
    private readonly AuthRuntime<TUser> _runtime;

    public LoginService(AuthRuntime<TUser> runtime)
    {
        _runtime = runtime;
    }

    public async Task<Result<RefreshTokenDto>> Login(string username, string password)
    {
        _runtime.Logger.LogInformation("Tentativo login");
        _runtime.Logger.LogDebug("Tentativo login per utente {username}", username);

        var validationResult = InputValidators.ValidateLogin(username, password);
        if (validationResult.IsFailure)
        {
            return Result.Fail<RefreshTokenDto>(validationResult.Error);
        }

        // Pre-auth throttling is IP scoped to reduce account lockout abuse.
        var ipScopeKey = string.Empty;
        var rateLimitKey = AuthRuntime<TUser>.NormalizeIdentifier(username);
        var preAuthRateLimit = await _runtime.RateLimitGuard.EnsureNotBlockedAndRegisterAttempt(
            RateLimitRequestType.Login,
            ipScopeKey,
            "utente bloccato",
            "utente bloccato per troppi tentativi");
        if (preAuthRateLimit.IsFailure)
        {
            _runtime.Logger.LogWarning("Login bloccato");
            _runtime.Logger.LogDebug("Login bloccato per utente {username} (ip policy pre-auth)", username);
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.UserBlocked, preAuthRateLimit.Error);
        }

        var user = await _runtime.Repository.GetUserByUsernameAsync(username);
        byte[] storedHash;
        byte[] saltBytes;
        var userExists = user != null;

        if (!userExists)
        {
            // Keep a comparable crypto path for unknown users to reduce timing side-channels.
            saltBytes = RandomNumberGenerator.GetBytes(16);
            storedHash = _runtime.HashPassword("invalid-password", saltBytes);
        }
        else
        {
            try
            {
                storedHash = Convert.FromBase64String(user!.Password);
                saltBytes = Convert.FromBase64String(user.Salt);
            }
            catch
            {
                return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.UserDataInvalid);
            }
        }

        var testHashed = _runtime.HashPassword(password, saltBytes);
        var isValid = userExists
            && user!.EmailVerified
            && CryptographicOperations.FixedTimeEquals(storedHash, testHashed);
        if (!isValid)
        {
            if (!userExists)
            {
                _runtime.Logger.LogWarning("Login fallito: utente non trovato");
                _runtime.Logger.LogDebug("Login fallito: utente {username} non trovato", username);
                return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidCredentials);
            }

            if (!user.EmailVerified)
            {
                _runtime.Logger.LogWarning("Login fallito: email non verificata");
                _runtime.Logger.LogDebug("Login fallito: email non verificata per utente {username}", username);
                return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidCredentials);
            }

            // Account-specific counter increments only after confirming account existence.
            var accountLimit = await _runtime.RateLimitGuard.RegisterAttempt(
                RateLimitRequestType.Login,
                rateLimitKey,
                "utente bloccato per troppi tentativi");
            if (accountLimit.IsFailure)
            {
                _runtime.Logger.LogWarning("Login bloccato (rate limit account)");
                _runtime.Logger.LogDebug("Login bloccato per utente {username} (account rate limit)", username);
                return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.RateLimited, accountLimit.Error);
            }

            _runtime.Logger.LogWarning("Login fallito: credenziali non valide");
            _runtime.Logger.LogDebug("Login fallito: password errata per utente {username}", username);
            return AuthErrorCatalog.Fail<RefreshTokenDto>(AuthErrorCode.InvalidCredentials);
        }

        var accessToken = _runtime.TokenService.GenerateAccessToken(user);
        var refreshToken = await _runtime.TokenService.CreateRefreshToken(user);
        await _runtime.RateLimitService.Reset(RateLimitRequestType.Login, rateLimitKey);

        _runtime.Logger.LogInformation("Login riuscito");
        _runtime.Logger.LogDebug("Login riuscito per utente {username}", username);

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
}
