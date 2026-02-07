using System.Security.Cryptography;
using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using Microsoft.Extensions.Logging;

namespace AuthLibrary.Services;

internal sealed class AuthRuntime<TUser> where TUser : class, IAuthUser
{
    public IAuthRepository<TUser> Repository { get; }
    public IMailService MailService { get; }
    public IMailTemplateService TemplateService { get; }
    public ITokenService<TUser> TokenService { get; }
    public IRateLimitService RateLimitService { get; }
    public AuthSettings AuthSettings { get; }
    public MailSettings MailSettings { get; }
    public ILogger<AuthService<TUser>> Logger { get; }
    public IPasswordValidator PasswordValidator { get; }
    public IExternalTokenValidator ExternalTokenValidator { get; }
    public IExternalUserFactory<TUser>? ExternalUserFactory { get; }
    public RateLimitGuard RateLimitGuard { get; }
    public bool RequireTransactionalRepository { get; }

    private readonly string _pepper;

    public AuthRuntime(
        IAuthRepository<TUser> repository,
        string pepper,
        IMailService mailService,
        ITokenService<TUser> tokenService,
        IRateLimitService rateLimitService,
        IMailTemplateService templateService,
        bool requireTransactionalRepository,
        AuthSettings authSettings,
        MailSettings mailSettings,
        ILogger<AuthService<TUser>> logger,
        IPasswordValidator passwordValidator,
        IExternalTokenValidator externalTokenValidator,
        IExternalUserFactory<TUser>? externalUserFactory)
    {
        Repository = repository;
        _pepper = pepper;
        MailService = mailService;
        TokenService = tokenService;
        RateLimitService = rateLimitService;
        TemplateService = templateService;
        RequireTransactionalRepository = requireTransactionalRepository;
        AuthSettings = authSettings;
        MailSettings = mailSettings;
        Logger = logger;
        PasswordValidator = passwordValidator;
        ExternalTokenValidator = externalTokenValidator;
        ExternalUserFactory = externalUserFactory;
        RateLimitGuard = new RateLimitGuard(rateLimitService);

        if (RequireTransactionalRepository && repository is not ITransactionalAuthRepository<TUser>)
        {
            throw new InvalidOperationException("Registrare ITransactionalAuthRepository<TUser> per garantire operazioni atomiche.");
        }

        if (!RequireTransactionalRepository && repository is not ITransactionalAuthRepository<TUser>)
        {
            Logger.LogWarning("Repository non transazionale: alcune operazioni multi-step non saranno atomiche.");
        }
    }

    public byte[] HashPassword(string password, byte[] salt)
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

    public (string plainToken, string tokenHash) GenerateSecureToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var plainToken = Convert.ToBase64String(bytes);
        var tokenHash = HashToken(plainToken);
        return (plainToken, tokenHash);
    }

    public static string HashToken(string token)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public static string NormalizeEmail(string email)
    {
        return string.IsNullOrWhiteSpace(email) ? string.Empty : email.Trim().ToLowerInvariant();
    }

    public static string NormalizeIdentifier(string identifier)
    {
        return string.IsNullOrWhiteSpace(identifier) ? string.Empty : identifier.Trim().ToLowerInvariant();
    }

    public Task ExecuteInTransactionAsync(Func<Task> operation)
    {
        if (Repository is ITransactionalAuthRepository<TUser> transactionalRepository)
        {
            return transactionalRepository.ExecuteInTransactionAsync(operation);
        }

        if (RequireTransactionalRepository)
        {
            throw new InvalidOperationException("Repository non transazionale: operazione bloccata per sicurezza.");
        }

        return operation();
    }
}
