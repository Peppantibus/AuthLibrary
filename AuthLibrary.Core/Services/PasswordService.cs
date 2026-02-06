using System.Security.Cryptography;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using AuthLibrary.Validation;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class PasswordService<TUser> : IPasswordFlowService<TUser> where TUser : class, IAuthUser
{
    private readonly AuthRuntime<TUser> _runtime;
    private readonly EmailVerificationService<TUser> _emailVerificationService;

    public PasswordService(AuthRuntime<TUser> runtime, EmailVerificationService<TUser> emailVerificationService)
    {
        _runtime = runtime;
        _emailVerificationService = emailVerificationService;
    }

    public async Task<Result<string>> RecoveryPassword(string email)
    {
        _runtime.Logger.LogInformation("Richiesta reset password");
        _runtime.Logger.LogDebug("Richiesta reset password");
        const string genericResponse = "Se l'email e registrata, ti abbiamo inviato un link per il reset.";

        var normalizedEmail = AuthRuntime<TUser>.NormalizeEmail(email);
        var emailValidation = InputValidators.ValidateEmail(normalizedEmail);
        if (emailValidation.IsFailure)
        {
            return Result.Ok(genericResponse);
        }

        var gateResult = await _runtime.RateLimitGuard.EnsureNotBlockedOrInCooldown(
            RateLimitRequestType.ResetPassword,
            normalizedEmail,
            "Se l'email e registrata, ti abbiamo inviato un link per il reset.",
            "Se l'email e registrata, ti abbiamo inviato un link per il reset.");
        if (gateResult.IsFailure)
        {
            _runtime.Logger.LogWarning("RecoveryPassword bloccato o in cooldown");
            _runtime.Logger.LogDebug("RecoveryPassword bloccato/cooldown");
            return Result.Ok(gateResult.Error);
        }

        var existingEntry = await _runtime.Repository.GetUserByEmailAsync(normalizedEmail);
        if (existingEntry == null)
        {
            await _runtime.RateLimitService.RegisterAttempted(RateLimitRequestType.ResetPassword, normalizedEmail);
            _runtime.Logger.LogInformation("RecoveryPassword richiesto per email non esistente");
            _runtime.Logger.LogDebug("RecoveryPassword richiesto per email non esistente");
            return Result.Ok(genericResponse);
        }

        var (plainToken, tokenHash) = _runtime.GenerateSecureToken();
        await ExecuteInTransaction(async () =>
        {
            await _runtime.Repository.RemovePasswordResetTokensByUserIdAsync(existingEntry.Id);
            await _runtime.Repository.AddPasswordResetTokenAsync(new PasswordResetToken
            {
                UserId = existingEntry.Id,
                TokenHash = tokenHash,
                ExpiresAt = DateTime.UtcNow.AddMinutes(30)
            });
            await _runtime.Repository.SaveChangesAsync();
        });

        Result emailResult;
        try
        {
            emailResult = await _emailVerificationService.SendAuthEmail(
                RateLimitRequestType.ResetPassword,
                normalizedEmail,
                existingEntry.Username,
                plainToken,
                "ResetPassword.html",
                "Recupero Password",
                "/reset-password?token=");
        }
        catch (Exception ex)
        {
            _runtime.Logger.LogError(ex, "RecoveryPassword invio email fallito");
            return Result.Ok(genericResponse);
        }

        if (emailResult.IsFailure)
        {
            _runtime.Logger.LogWarning(
                "RecoveryPassword invio email interno fallito con code {code}",
                emailResult.ErrorCode);
            _runtime.Logger.LogDebug("RecoveryPassword invio email interno fallito");
            return Result.Ok(genericResponse);
        }

        return Result.Ok(genericResponse);
    }

    public async Task<Result<bool>> ResetPasswordRedirect(string token)
    {
        var tokenValidation = InputValidators.ValidateToken(token);
        if (tokenValidation.IsFailure)
        {
            _runtime.Logger.LogWarning("ResetPassword: token non valido");
            return Result.Ok(false);
        }

        var tokenHash = AuthRuntime<TUser>.HashToken(token);
        var entry = await _runtime.Repository.GetPasswordResetTokenAsync(tokenHash);
        if (entry == null)
        {
            _runtime.Logger.LogWarning("ResetPassword: token non valido");
            return Result.Ok(false);
        }
        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _runtime.Logger.LogWarning("ResetPassword: token scaduto");
            await ExecuteInTransaction(async () =>
            {
                await _runtime.Repository.RemovePasswordResetTokenAsync(entry);
                await _runtime.Repository.SaveChangesAsync();
            });
            return Result.Ok(false);
        }

        return Result.Ok(true);
    }

    public async Task<Result<bool>> ResetPassword(ResetPasswordDto body)
    {
        var validationResult = InputValidators.ValidateResetPassword(body);
        if (validationResult.IsFailure)
        {
            return AuthErrorCatalog.Fail<bool>(AuthErrorCode.UserDataInvalid, validationResult.Error);
        }
        if (body.Password != body.ConfirmPassword)
        {
            return AuthErrorCatalog.Fail<bool>(AuthErrorCode.UserDataInvalid, "password e confirm password devono essere uguali");
        }
        if (!_runtime.PasswordValidator.IsValid(body.Password, out var passwordError))
        {
            _runtime.Logger.LogWarning("ResetPassword fallito: password debole");
            return AuthErrorCatalog.Fail<bool>(AuthErrorCode.UserDataInvalid, passwordError);
        }

        var tokenHash = AuthRuntime<TUser>.HashToken(body.Token);
        var entry = await _runtime.Repository.GetPasswordResetTokenAsync(tokenHash);
        if (entry == null)
        {
            return Result.Ok(false);
        }
        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            await ExecuteInTransaction(async () =>
            {
                await _runtime.Repository.RemovePasswordResetTokenAsync(entry);
                await _runtime.Repository.SaveChangesAsync();
            });
            return Result.Ok(false);
        }

        var user = await _runtime.Repository.GetUserByIdAsync(entry.UserId);
        if (user == null)
        {
            return AuthErrorCatalog.Fail<bool>(AuthErrorCode.RecoveryError);
        }

        var salt = RandomNumberGenerator.GetBytes(16);
        var hashedPw = _runtime.HashPassword(body.Password, salt);
        user.Password = Convert.ToBase64String(hashedPw);
        user.Salt = Convert.ToBase64String(salt);
        user.PasswordUpdatedAt = DateTime.UtcNow;

        await ExecuteInTransaction(async () =>
        {
            await _runtime.Repository.RemovePasswordResetTokensByUserIdAsync(user.Id);
            await _runtime.Repository.UpdateUserAsync(user);
            await _runtime.Repository.SaveChangesAsync();
        });

        _runtime.Logger.LogDebug("Password resettata con successo");
        return Result.Ok(true);
    }

    private Task ExecuteInTransaction(Func<Task> operation)
    {
        return _runtime.ExecuteInTransactionAsync(operation);
    }
}
