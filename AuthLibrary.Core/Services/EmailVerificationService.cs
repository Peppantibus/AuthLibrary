using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class EmailVerificationService<TUser> where TUser : class, IAuthUser
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

        var normalizedEmail = AuthRuntime<TUser>.NormalizeEmail(email);

        var blockedResult = await _runtime.RateLimitGuard.EnsureNotBlocked(
            RateLimitRequestType.VerifyEmail,
            normalizedEmail,
            "Troppi tentativi. Riprova più tardi.");
        if (blockedResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Resend bloccato (rate limit)");
            _runtime.Logger.LogDebug("Resend bloccato per email {email} (rate limit)", email);
            return Result.Fail(blockedResult.Error);
        }

        var cooldownResult = await _runtime.RateLimitGuard.EnsureNotInCooldown(
            RateLimitRequestType.VerifyEmail,
            normalizedEmail,
            "Attendi prima di richiedere un nuovo invio.");
        if (cooldownResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Resend in cooldown");
            _runtime.Logger.LogDebug("Resend in cooldown per email {email}", email);
            return Result.Fail(cooldownResult.Error);
        }

        var user = await _runtime.Repository.GetUserByEmailAsync(normalizedEmail);
        if (user == null)
        {
            await _runtime.RateLimitService.RegisterAttempted(RateLimitRequestType.VerifyEmail, normalizedEmail);
            return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link di verifica.");
        }

        if (user.EmailVerified)
        {
            _runtime.Logger.LogInformation("Resend richiesto per email gia verificata");
            _runtime.Logger.LogDebug("Resend richiesto per email gia verificata {email}", email);
            return Result.Ok("Se l'email è registrata e non ancora verificata, ti abbiamo inviato un link di verifica.");
        }

        var (plainToken, tokenHash) = _runtime.GenerateSecureToken();
        await _runtime.Repository.RemoveEmailVerifiedTokensByUserIdAsync(user.Id);
        await _runtime.Repository.AddEmailVerifiedTokenAsync(new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        });
        await _runtime.Repository.SaveChangesAsync();

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
            return Result.Fail(emailResult.Error);
        }

        _runtime.Logger.LogInformation("Email di verifica reinviata");
        _runtime.Logger.LogDebug("Email di verifica reinviata a {email}", email);
        return Result.Ok("Email di verifica inviata.");
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
            await _runtime.Repository.RemoveEmailVerifiedTokenAsync(entry);
            await _runtime.Repository.SaveChangesAsync();
            return Result.Ok(false);
        }

        var user = await _runtime.Repository.GetUserByIdAsync(entry.UserId);
        if (user != null)
        {
            user.EmailVerified = true;
            await _runtime.Repository.UpdateUserAsync(user);
        }

        await _runtime.Repository.RemoveEmailVerifiedTokensByUserIdAsync(entry.UserId);
        await _runtime.Repository.SaveChangesAsync();

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

        var blockedResult = await _runtime.RateLimitGuard.EnsureNotBlocked(type, email, "utente bloccato");
        if (blockedResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Block RATE LIMIT {type}", type);
            _runtime.Logger.LogDebug("Block RATE LIMIT {type} per email {email}", type, email);
            return Result.Fail(blockedResult.Error);
        }

        var cooldownResult = await _runtime.RateLimitGuard.EnsureNotInCooldown(type, email, "utente in cooldown");
        if (cooldownResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Cooldown attivo (tipo {type})", type);
            _runtime.Logger.LogDebug("Cooldown attivo per email {email} (tipo {type})", email, type);
            return Result.Fail(cooldownResult.Error);
        }

        var attemptResult = await _runtime.RateLimitGuard.RegisterAttempt(type, email, "troppi tentativi, utente bloccato temporaneamente");
        if (attemptResult.IsFailure)
        {
            _runtime.Logger.LogWarning("Tentativi eccessivi per {type}. Utente bloccato.", type);
            _runtime.Logger.LogDebug("Tentativi eccessivi per {type} email {email}. Utente bloccato.", type, email);
            return Result.Fail(attemptResult.Error);
        }

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

        _runtime.Logger.LogInformation("Email {type} inviata", type);
        _runtime.Logger.LogDebug("Email {type} inviata a {email}", type, email);
        await _runtime.RateLimitService.StartCooldown(type, email, TimeSpan.FromSeconds(60));
        return Result.Ok();
    }
}
