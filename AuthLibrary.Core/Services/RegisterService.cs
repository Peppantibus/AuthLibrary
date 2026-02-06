using System.Security.Cryptography;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class RegisterService<TUser> : IRegisterService<TUser> where TUser : class, IAuthUser
{
    private readonly AuthRuntime<TUser> _runtime;
    private readonly EmailVerificationService<TUser> _emailVerificationService;

    public RegisterService(AuthRuntime<TUser> runtime, EmailVerificationService<TUser> emailVerificationService)
    {
        _runtime = runtime;
        _emailVerificationService = emailVerificationService;
    }

    public async Task<Result> AddUser(TUser user)
    {
        var normalizedEmail = AuthRuntime<TUser>.NormalizeEmail(user.Email);
        if (!string.IsNullOrWhiteSpace(normalizedEmail))
        {
            user.Email = normalizedEmail;
        }

        var blockedResult = await _runtime.RateLimitGuard.EnsureNotBlocked(
            RateLimitRequestType.Register,
            normalizedEmail,
            "utente bloccato");
        if (blockedResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Registrazione bloccata");
            _runtime.Logger.LogDebug("Registrazione bloccata per email {email}", user.Email);
            return Result.Fail(blockedResult.Error);
        }

        var attemptResult = await _runtime.RateLimitGuard.RegisterAttempt(
            RateLimitRequestType.Register,
            normalizedEmail,
            "utente bloccato per troppi tentativi");
        if (attemptResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Registrazione bloccata (rate limit)");
            _runtime.Logger.LogDebug("Registrazione bloccata per email {email} (rate limit)", user.Email);
            return Result.Fail(attemptResult.Error);
        }

        var exists = await _runtime.Repository.UserExistsAsync(user.Username, normalizedEmail);
        if (exists)
        {
            _runtime.Logger.LogWarning("Tentativo di registrazione con email/username gia usata");
            _runtime.Logger.LogDebug("Tentativo di registrazione con email/username gia usata: {email}", user.Email);
            return Result.Fail("registrazione non valida");
        }

        if (!_runtime.PasswordValidator.IsValid(user.Password, out var passwordError))
        {
            _runtime.Logger.LogWarning("Registrazione fallita: password debole");
            _runtime.Logger.LogDebug("Registrazione fallita: password debole per email {email}", user.Email);
            return Result.Fail(passwordError);
        }

        var salt = RandomNumberGenerator.GetBytes(16);
        var hashedPw = _runtime.HashPassword(user.Password, salt);
        user.Password = Convert.ToBase64String(hashedPw);
        user.Salt = Convert.ToBase64String(salt);
        user.EmailVerified = false;

        var (plainToken, tokenHash) = _runtime.GenerateSecureToken();
        var emailVerified = new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        await ExecuteInTransaction(async () =>
        {
            await _runtime.Repository.AddUserAsync(user);
            await _runtime.Repository.AddEmailVerifiedTokenAsync(emailVerified);
            await _runtime.Repository.SaveChangesAsync();
        });

        Result emailResult;
        try
        {
            emailResult = await _emailVerificationService.SendAuthEmail(
                RateLimitRequestType.VerifyEmail,
                normalizedEmail,
                user.Username,
                plainToken,
                "VerifyEmail.html",
                "Verifica email",
                "/verify-email?token=");
        }
        catch (Exception ex)
        {
            _runtime.Logger.LogError(ex, "Invio email di verifica fallito per {email}", user.Email);
            emailResult = Result.Fail("Impossibile inviare email di verifica. Riprova piu tardi.");
        }

        if (emailResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Invio email fallito, rollback registrazione");
            _runtime.Logger.LogDebug("Invio email fallito per {email}, rollback registrazione", user.Email);
            await ExecuteInTransaction(async () =>
            {
                await _runtime.Repository.RemoveUserAsync(user);
                await _runtime.Repository.RemoveEmailVerifiedTokenAsync(emailVerified);
                await _runtime.Repository.SaveChangesAsync();
            });
            return Result.Fail("Impossibile inviare email di verifica. Riprova piu tardi.");
        }

        _runtime.Logger.LogInformation("Registrazione completata");
        _runtime.Logger.LogDebug("Registrazione completata per utente {email}", user.Email);
        return Result.Ok();
    }

    private Task ExecuteInTransaction(Func<Task> operation)
    {
        if (_runtime.Repository is ITransactionalAuthRepository<TUser> transactionalRepository)
        {
            return transactionalRepository.ExecuteInTransactionAsync(operation);
        }

        return operation();
    }
}