using System.Security.Cryptography;
using Chat.AuthLibrary.Configuration;
using Chat.AuthLibrary.Enum;
using Chat.AuthLibrary.Interfaces;
using Chat.AuthLibrary.Models;
using Chat.AuthLibrary.Models.Dto;
using Chat.AuthLibrary.Models.Dto.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Chat.AuthLibrary.Services;

public class AuthService<TUser> : IAuthService<TUser> where TUser : class, IAuthUser
{
    private readonly IAuthRepository<TUser> _repository;
    private readonly string _pepper;
    private readonly IMailService _mailService;
    private readonly IMailTemplateService _templateService;
    private readonly ITokenService<TUser> _tokenService;
    private readonly IRateLimitService _rateLimitService;
    private readonly AuthSettings _authSettings;
    private readonly MailSettings _mailSettings;
    private readonly ILogger<AuthService<TUser>> _logger;
    private readonly IPasswordValidator _passwordValidator;

    public AuthService(
        IAuthRepository<TUser> repository,
        IOptions<SecuritySettings> securitySettings,
        IMailService mailService,
        ITokenService<TUser> tokenService,
        IRateLimitService rateLimitService,
        IMailTemplateService templateService,
        IOptions<AuthSettings> authSettings,
        IOptions<MailSettings> mailSettings,
        ILogger<AuthService<TUser>> logger,
        IPasswordValidator passwordValidator)
    {
        _repository = repository;
        _pepper = securitySettings.Value.Pepper;
        _mailService = mailService;
        _tokenService = tokenService;
        _rateLimitService = rateLimitService;
        _templateService = templateService;
        _authSettings = authSettings.Value;
        _mailSettings = mailSettings.Value;
        _logger = logger;
        _passwordValidator = passwordValidator;
    }

    public async Task<Result<RefreshTokenDto>> Login(string username, string password)
    {
        _logger.LogInformation("Tentativo login per utente {username}", username);
        
        bool limitReached = await _rateLimitService.RegisterAttempted(RateLimitRequestType.Login, username);
        if (limitReached)
        {
            _logger.LogWarning("Login bloccato per utente {username} (rate limit)", username);
            return Result.Fail<RefreshTokenDto>("utente bloccato per troppi tentativi");
        }

        bool isBlocked = await _rateLimitService.IsBlocked(RateLimitRequestType.Login, username);
        if (isBlocked)
        {
             _logger.LogWarning("Login bloccato per utente {username} (pre-existing lock)", username);
             return Result.Fail<RefreshTokenDto>("utente bloccato");
        }

        var user = await _repository.GetUserByUsernameAsync(username);
        if (user == null)
        {
            _logger.LogWarning("Login fallito: utente {username} non trovato", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide");
        }
        if (!user.EmailVerified)
        {
            _logger.LogWarning("Login fallito: email non verificata per utente {username}", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide"); // Same message to prevent enumeration
        }
        var salt = user.Salt;

        byte[] storedHash;
        byte[] saltBytes;
        try 
        {
             storedHash = Convert.FromBase64String(user.Password);
             saltBytes = Convert.FromBase64String(salt);
        }
        catch
        {
            return Result.Fail<RefreshTokenDto>("Errore dati utente");
        }

        var testHashed = HashPassword(password, saltBytes);

        bool isValid = CryptographicOperations.FixedTimeEquals(storedHash, testHashed);

        if (!isValid) {
            _logger.LogWarning("Login fallito: password errata per utente {username}", username);
            return Result.Fail<RefreshTokenDto>("Credenziali non valide");
        }

        var accesstokenResponse = _tokenService.GenerateAccessToken(user);
        var refreshToken = await _tokenService.CreateRefreshToken(user);

        await _rateLimitService.Reset(RateLimitRequestType.Login, username);

        _logger.LogInformation("Login riuscito per utente {username}", username);

        return Result.Ok(new RefreshTokenDto
        {
            NewRefreshToken = refreshToken.PlainToken,
            RefreshTokenExpiresAt = refreshToken.ExpiresAt,
            AccessToken = accesstokenResponse,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Name = user.Name,
                LastName = user.LastName,
            }
        });
    }

    public async Task<Result> AddUser(TUser user)
    {
        bool isBlocked = await _rateLimitService.IsBlocked(RateLimitRequestType.Register, user.Email);

        if (isBlocked)
        {
            _logger.LogWarning("Registrazione bloccata per email {email}", user.Email);
            return Result.Fail("utente bloccato");
        }

        bool exists = await _repository.UserExistsAsync(user.Username, user.Email);

        if (exists)
        {
            await _rateLimitService.RegisterAttempted(RateLimitRequestType.Register, user.Email);
            _logger.LogWarning("Tentativo di registrazione con email/username già usata: {email}", user.Email);
            return Result.Fail("utente già esistente, riprova con un o altro username o email");
        }

        // Password validation
        if (!_passwordValidator.IsValid(user.Password, out string passwordError))
        {
            _logger.LogWarning("Registrazione fallita: password debole per email {email}", user.Email);
            return Result.Fail(passwordError);
        }

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hashedPw = HashPassword(user.Password, salt);

        user.Password = Convert.ToBase64String(hashedPw);
        user.Salt = Convert.ToBase64String(salt);
        user.EmailVerified = false; // SECURITY: Always force false, prevent bypass

        await _repository.AddUserAsync(user);

        var (plainToken, tokenHash) = GenerateSecureToken();

        var emailVerified = new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
        };

        await _repository.AddEmailVerifiedTokenAsync(emailVerified);
        await _repository.SaveChangesAsync();

        // ATOMIC: If email fails, rollback user creation
        var emailResult = await SendAuthEmail(RateLimitRequestType.VerifyEmail, user.Email, user.Username, plainToken, "VerifyEmail.html", "Verifica email", "/verify-email?token=");
        
        if (emailResult.IsFailure)
        {
            // Rollback: remove user and token
            _logger.LogWarning("Invio email fallito per {email}, rollback registrazione", user.Email);
            await _repository.RemoveUserAsync(user);
            await _repository.RemoveEmailVerifiedTokenAsync(emailVerified);
            await _repository.SaveChangesAsync();
            
            return Result.Fail("Impossibile inviare email di verifica. Riprova più tardi.");
        }

        _logger.LogInformation("Registrazione completata per utente {email}", user.Email);
        return Result.Ok();
    }

    public async Task<Result> ResendVerificationEmail(string email)
    {
        _logger.LogInformation("Richiesta resend email verifica per {email}", email);

        // Rate limit check
        if (await _rateLimitService.IsBlocked(RateLimitRequestType.VerifyEmail, email))
        {
            _logger.LogWarning("Resend bloccato per email {email} (rate limit)", email);
            return Result.Fail("Troppi tentativi. Riprova più tardi.");
        }

        if (await _rateLimitService.IsInCooldown(RateLimitRequestType.VerifyEmail, email))
        {
            _logger.LogWarning("Resend in cooldown per email {email}", email);
            return Result.Fail("Attendi prima di richiedere un nuovo invio.");
        }

        var user = await _repository.GetUserByEmailAsync(email);

        if (user == null)
        {
            // Generic message to prevent enumeration
            await _rateLimitService.RegisterAttempted(RateLimitRequestType.VerifyEmail, email);
            return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link di verifica.");
        }

        if (user.EmailVerified)
        {
            // SECURITY: Generic message to prevent account enumeration
            _logger.LogInformation("Resend richiesto per email già verificata {email}", email);
            return Result.Ok("Se l'email è registrata e non ancora verificata, ti abbiamo inviato un link di verifica.");
        }

        // Generate new token
        var (plainToken, tokenHash) = GenerateSecureToken();

        await _repository.RemoveEmailVerifiedTokensByUserIdAsync(user.Id);

        var emailVerified = new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
        };

        await _repository.AddEmailVerifiedTokenAsync(emailVerified);
        await _repository.SaveChangesAsync();

        var emailResult = await SendAuthEmail(RateLimitRequestType.VerifyEmail, email, user.Username, plainToken, "VerifyEmail.html", "Verifica email", "/verify-email?token=");
        
        if (emailResult.IsFailure)
        {
            return Result.Fail(emailResult.Error);
        }

        _logger.LogInformation("Email di verifica reinviata a {email}", email);
        return Result.Ok("Email di verifica inviata.");
    }

    public async Task<Result<string>> RecoveryPassword(string email)
    {
        _logger.LogInformation("Richiesta reset password per email {email}", email);

        // Rate limit check BEFORE creating token (prevent DB spam)
        if (await _rateLimitService.IsBlocked(RateLimitRequestType.ResetPassword, email))
        {
            _logger.LogWarning("RecoveryPassword bloccato per email {email} (rate limit)", email);
            return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link per il reset."); // Generic message
        }

        if (await _rateLimitService.IsInCooldown(RateLimitRequestType.ResetPassword, email))
        {
            _logger.LogWarning("RecoveryPassword in cooldown per email {email}", email);
            return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link per il reset.");
        }

        var existingEntry = await _repository.GetUserByEmailAsync(email);

        if (existingEntry == null)
        {
            // Register attempt even for non-existent emails to prevent enumeration
            await _rateLimitService.RegisterAttempted(RateLimitRequestType.ResetPassword, email);
            _logger.LogInformation("RecoveryPassword richiesto per email non esistente {email}", email);
            return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link per il reset.");
        }

        var (plainToken, tokenHash) = GenerateSecureToken();

        await _repository.RemovePasswordResetTokensByUserIdAsync(existingEntry.Id);

        var entryPassword = new PasswordResetToken
        {
            UserId = existingEntry.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
        };

        await _repository.AddPasswordResetTokenAsync(entryPassword);
        await _repository.SaveChangesAsync();

        var emailResult = await SendAuthEmail(RateLimitRequestType.ResetPassword, email, existingEntry.Username, plainToken, "ResetPassword.html", "Recupero Password", "/reset-password?token=");
         if (emailResult.IsFailure)
        {
             return Result.Fail<string>(emailResult.Error);
        }

        return Result.Ok("Se l'email è registrata, ti abbiamo inviato un link per il reset.");
    }

    public async Task<Result<bool>> ResetPasswordRedirect(string token)
    {
        var tokenHash = HashToken(token);
        var entry = await _repository.GetPasswordResetTokenAsync(tokenHash);

        if (entry == null)
        {
            _logger.LogWarning("ResetPassword: il token non esiste");
            return Result.Ok(false);
        }

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("ResetPassword: token scaduto");
            await _repository.RemovePasswordResetTokenAsync(entry);
            await _repository.SaveChangesAsync();
             return Result.Ok(false);
        }

        return Result.Ok(true);
    }

    public async Task<Result<bool>> ResetPassword(ResetPasswordDto body)
    {
        if (body.Password != body.ConfirmPassword)
        {
            return Result.Fail<bool>("password e confirm password devono essere uguali");
        }

        // Password validation
        if (!_passwordValidator.IsValid(body.Password, out string passwordError))
        {
            _logger.LogWarning("ResetPassword fallito: password debole");
            return Result.Fail<bool>(passwordError);
        }

        var tokenHash = HashToken(body.Token);
        var entry = await _repository.GetPasswordResetTokenAsync(tokenHash);
        if (entry == null) return Result.Ok(false);

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            // CLEANUP: Remove expired token to prevent DB accumulation
            await _repository.RemovePasswordResetTokenAsync(entry);
            await _repository.SaveChangesAsync();
            return Result.Ok(false);
        }

        var user = await _repository.GetUserByIdAsync(entry.UserId);

        if (user == null)
        {
             return Result.Fail<bool>("errore durante il recupero");
        }

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hashedPw = HashPassword(body.Password, salt);

        user.Password = Convert.ToBase64String(hashedPw);
        user.Salt = Convert.ToBase64String(salt);
        user.PasswordUpdatedAt = DateTime.UtcNow;

        await _repository.RemovePasswordResetTokensByUserIdAsync(user.Id);
        await _repository.UpdateUserAsync(user); 
        await _repository.SaveChangesAsync();
        
        _logger.LogInformation("Password resettata per utente id {id}", user.Id);

        return Result.Ok(true);
    }

    public async Task<Result<bool>> VerifyMail(string token)
    {
        var tokenHash = HashToken(token);
        var entry = await _repository.GetEmailVerifiedTokenAsync(tokenHash);

        if (entry == null)
        {
            _logger.LogWarning("VerifyMail: il token non esiste");
            return Result.Ok(false);
        }

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("VerifyMail: token scaduto, cleanup");
            // CLEANUP: Remove expired token to prevent DB accumulation
            await _repository.RemoveEmailVerifiedTokenAsync(entry);
            await _repository.SaveChangesAsync();
            return Result.Ok(false);
        }

        var user = await _repository.GetUserByIdAsync(entry.UserId);
        if (user != null)
        {
            user.EmailVerified = true;
            await _repository.UpdateUserAsync(user);
        }
             
        await _repository.RemoveEmailVerifiedTokensByUserIdAsync(entry.UserId);
        await _repository.SaveChangesAsync();

        _logger.LogInformation("Email verificata con successo per utente {email}", user?.Email);

        return Result.Ok(true);
    }

    private byte[] HashPassword(string password, byte[] salt)
    {
        var config = new Isopoh.Cryptography.Argon2.Argon2Config
        {
            Type = Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
            Version = Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
            TimeCost = 4,
            MemoryCost = 65536,
            Lanes = 4,
            Threads = 4,
            Password = System.Text.Encoding.UTF8.GetBytes(password + _pepper),
            Salt = salt,
            HashLength = 32
        };
        
        using var argon2 = new Isopoh.Cryptography.Argon2.Argon2(config);
        using var hash = argon2.Hash();
        return hash.Buffer.ToArray();
    }
    
    /// <summary>
    /// Generates a secure random token (32 bytes) and returns both the plain token and its SHA256 hash.
    /// </summary>
    private (string plainToken, string tokenHash) GenerateSecureToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var plainToken = Convert.ToBase64String(bytes);
        var tokenHash = HashToken(plainToken);
        return (plainToken, tokenHash);
    }

    /// <summary>
    /// Computes SHA256 hash of a token for secure storage.
    /// </summary>
    private static string HashToken(string token)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    private async Task<Result> SendAuthEmail(
     RateLimitRequestType type,
     string email,
     string username,
     string plainToken,
     string templateName,
     string subject,
     string urlPath)
    {
        _logger.LogDebug("Preparazione invio email {type} a {email}", type, email);

        if (await _rateLimitService.IsBlocked(type, email))
        {
            _logger.LogWarning("Block RATE LIMIT {type} per email {email}", type, email);
            return Result.Fail("utente bloccato");
        }

        if (await _rateLimitService.IsInCooldown(type, email))
        {
            _logger.LogWarning("Cooldown attivo per email {email} (tipo {type})", email, type);
            return Result.Fail("utente in cooldown");
        }
        
        bool attemptLimitReached = await _rateLimitService.RegisterAttempted(type, email);
        if (attemptLimitReached)
        {
            _logger.LogWarning("Tentativi eccessivi per {type} email {email}. Utente bloccato.", type, email);
            return Result.Fail("troppi tentativi, utente bloccato temporaneamente");
        }

        string baseUrl = _authSettings.FrontendUrl;
        string url = $"{baseUrl}{urlPath}{Uri.EscapeDataString(plainToken)}";

        var parameters = new Dictionary<string, string>
        {
            { "username", username },
            { "url", url }   
        };

        var html = await _templateService.RenderTemplateAsync(templateName, parameters);

        var mail = new MailDto
        {
            From = _mailSettings.AppMail,
            EmailTo = email,
            Subject = subject,
            Body = html,
            IsHtml = true
        };

        await _mailService.SendAsync(mail);
        _logger.LogInformation("Email {type} inviata a {email}", type, email);

        await _rateLimitService.StartCooldown(type, email, TimeSpan.FromSeconds(60));
        return Result.Ok();
    }
}
