using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto;
using AuthLibrary.Validation;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class EmailVerificationService<TUser> : IEmailVerificationService<TUser> where TUser : class, IAuthUser
{
    private readonly AuthRuntime<TUser> _runtime;

    public EmailVerificationService(AuthRuntime<TUser> runtime)
    {
        _runtime = runtime;
    }

    public async Task<Result> ResendVerificationEmail(string email)
    {
        _runtime.Logger.LogInformation("Richiesta resend email verifica");
        _runtime.Logger.LogDebug("Richiesta resend email verifica per {email}", email);
        const string genericResponse = "Se l'email e registrata e non ancora verificata, ti abbiamo inviato un link di verifica.";

        var normalizedEmail = AuthRuntime<TUser>.NormalizeEmail(email);
        var emailValidation = InputValidators.ValidateEmail(normalizedEmail);
        if (emailValidation.IsFailure)
        {
            return Result.Ok(genericResponse);
        }

        var gateResult = await _runtime.RateLimitGuard.EnsureNotBlockedOrInCooldown(
            RateLimitRequestType.VerifyEmail,
            normalizedEmail,
            "Troppi tentativi. Riprova piu tardi.",
            "Attendi prima di richiedere un nuovo invio.");
        if (gateResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Resend bloccato o in cooldown");
            _runtime.Logger.LogDebug("Resend bloccato/cooldown per email {email}", email);
            return AuthErrorCatalog.Fail(AuthErrorCode.RateLimited, gateResult.Error);
        }

        var user = await _runtime.Repository.GetUserByEmailAsync(normalizedEmail);
        if (user == null)
        {
            await ApplyResendTransition(normalizedEmail);
            return Result.Ok(genericResponse);
        }

        if (user.EmailVerified)
        {
            _runtime.Logger.LogInformation("Resend richiesto per email gia verificata");
            _runtime.Logger.LogDebug("Resend richiesto per email gia verificata {email}", email);
            await ApplyResendTransition(normalizedEmail);
            return Result.Ok(genericResponse);
        }

        var (plainToken, tokenHash) = _runtime.GenerateSecureToken();
        var token = new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        await ExecuteInTransaction(async () =>
        {
            await _runtime.Repository.RemoveEmailVerifiedTokensByUserIdAsync(user.Id);
            await _runtime.Repository.AddEmailVerifiedTokenAsync(token);
            await _runtime.Repository.SaveChangesAsync();
        });

        var emailResult = await SendAuthEmail(
            RateLimitRequestType.VerifyEmail,
            normalizedEmail,
            user.Username,
            plainToken,
            "VerifyEmail.html",
            "Verifica email",
            "/verify-email?token=");
        if (emailResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Resend interno fallito con code {code}", emailResult.ErrorCode);
            _runtime.Logger.LogDebug("Resend interno fallito per {email}: {error}", email, emailResult.Error);
            return Result.Ok(genericResponse);
        }

        _runtime.Logger.LogInformation("Email di verifica reinviata");
        _runtime.Logger.LogDebug("Email di verifica reinviata a {email}", email);
        return Result.Ok(genericResponse);
    }

    public async Task<Result<bool>> VerifyMail(string token)
    {
        var tokenHash = AuthRuntime<TUser>.HashToken(token);
        var entry = await _runtime.Repository.GetEmailVerifiedTokenAsync(tokenHash);
        if (entry == null)
        {
            _runtime.Logger.LogWarning("VerifyMail: token non valido");
            return Result.Ok(false);
        }

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _runtime.Logger.LogWarning("VerifyMail: token scaduto, cleanup");
            await ExecuteInTransaction(async () =>
            {
                await _runtime.Repository.RemoveEmailVerifiedTokenAsync(entry);
                await _runtime.Repository.SaveChangesAsync();
            });
            return Result.Ok(false);
        }

        var user = await _runtime.Repository.GetUserByIdAsync(entry.UserId);
        if (user == null)
        {
            await ExecuteInTransaction(async () =>
            {
                await _runtime.Repository.RemoveEmailVerifiedTokensByUserIdAsync(entry.UserId);
                await _runtime.Repository.SaveChangesAsync();
            });

            _runtime.Logger.LogWarning("VerifyMail: token valido ma utente non trovato");
            return Result.Ok(false);
        }

        await ExecuteInTransaction(async () =>
        {
            user.EmailVerified = true;
            await _runtime.Repository.UpdateUserAsync(user);
            await _runtime.Repository.RemoveEmailVerifiedTokensByUserIdAsync(entry.UserId);
            await _runtime.Repository.SaveChangesAsync();
        });

        _runtime.Logger.LogInformation("Email verificata con successo");
        _runtime.Logger.LogDebug("Email verificata con successo per utente {email}", user?.Email);
        return Result.Ok(true);
    }

    public async Task<Result> SendAuthEmail(
        RateLimitRequestType type,
        string email,
        string username,
        string plainToken,
        string templateName,
        string subject,
        string urlPath)
    {
        _runtime.Logger.LogDebug("Preparazione invio email {type} a {email}", type, email);

        var rateLimitResult = await _runtime.RateLimitGuard.EnsureNotBlockedOrInCooldownAndRegisterAttempt(
            type,
            email,
            "utente bloccato",
            "utente in cooldown",
            "troppi tentativi, utente bloccato temporaneamente");
        if (rateLimitResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Tentativi eccessivi per {type}. Utente bloccato.", type);
            _runtime.Logger.LogDebug("Tentativi eccessivi per {type} email {email}. Utente bloccato.", type, email);
            return AuthErrorCatalog.Fail(AuthErrorCode.RateLimited, rateLimitResult.Error);
        }

        try
        {
            var url = $"{_runtime.AuthSettings.FrontendUrl}{urlPath}{Uri.EscapeDataString(plainToken)}";
            var html = await _runtime.TemplateService.RenderTemplateAsync(templateName, new Dictionary<string, string>
            {
                { "username", username },
                { "url", url }
            });

            await _runtime.MailService.SendAsync(new MailDto
            {
                From = _runtime.MailSettings.AppMail,
                EmailTo = email,
                Subject = subject,
                Body = html,
                IsHtml = true
            });
        }
        catch (Exception ex)
        {
            _runtime.Logger.LogError(ex, "Invio email {type} fallito", type);
            return AuthErrorCatalog.Fail(AuthErrorCode.RecoveryError, "Impossibile inviare email. Riprova piu tardi.");
        }

        _runtime.Logger.LogInformation("Email {type} inviata", type);
        _runtime.Logger.LogDebug("Email {type} inviata a {email}", type, email);
        await _runtime.RateLimitService.StartCooldown(type, email, TimeSpan.FromSeconds(60));
        return Result.Ok();
    }

    private async Task ApplyResendTransition(string email)
    {
        await _runtime.RateLimitService.RegisterAttempted(RateLimitRequestType.VerifyEmail, email);
        await _runtime.RateLimitService.StartCooldown(RateLimitRequestType.VerifyEmail, email, TimeSpan.FromSeconds(60));
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
