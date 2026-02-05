using System.Security.Cryptography;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using AuthLibrary.Validation;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class LoginService<TUser> where TUser : class, IAuthUser
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

        var rateLimitKey = AuthRuntime<TUser>.NormalizeIdentifier(username);
        var rateLimitResult = await _runtime.RateLimitGuard.RegisterAttempt(
            RateLimitRequestType.Login,
            rateLimitKey,
            "utente bloccato per troppi tentativi");
        if (rateLimitResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Login bloccato (rate limit)");
            _runtime.Logger.LogDebug("Login bloccato per utente {username} (rate limit)", username);
            return Result.Fail<RefreshTokenDto>(rateLimitResult.Error);
        }

        var blockedResult = await _runtime.RateLimitGuard.EnsureNotBlocked(
            RateLimitRequestType.Login,
            rateLimitKey,
            "utente bloccato");
        if (blockedResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Login bloccato");
            _runtime.Logger.LogDebug("Login bloccato per utente {username} (pre-existing lock)", username);
            return Result.Fail<RefreshTokenDto>(blockedResult.Error);
        }

        var user = await _runtime.Repository.GetUserByUsernameAsync(username);
        if (user == null)
        {
            _runtime.Logger.LogWarning("Login fallito: utente non trovato");
            _runtime.Logger.LogDebug("Login fallito: utente {username} non trovato", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide");
        }

        if (!user.EmailVerified)
        {
            _runtime.Logger.LogWarning("Login fallito: email non verificata");
            _runtime.Logger.LogDebug("Login fallito: email non verificata per utente {username}", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide");
        }

        byte[] storedHash;
        byte[] saltBytes;
        try
        {
            storedHash = Convert.FromBase64String(user.Password);
            saltBytes = Convert.FromBase64String(user.Salt);
        }
        catch
        {
            return Result.Fail<RefreshTokenDto>("Errore dati utente");
        }

        var testHashed = _runtime.HashPassword(password, saltBytes);
        var isValid = CryptographicOperations.FixedTimeEquals(storedHash, testHashed);
        if (!isValid)
        {
            _runtime.Logger.LogWarning("Login fallito: credenziali non valide");
            _runtime.Logger.LogDebug("Login fallito: password errata per utente {username}", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide");
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
