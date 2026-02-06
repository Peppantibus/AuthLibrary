using System.Net;
using System.Net.Mail;
using System.Text;
using AuthLibrary.Enum;
using AuthLibrary.Services;
using Microsoft.Extensions.Configuration;

namespace AuthLibrary.Configuration;

internal sealed record ValidatedStartupSettings(bool RequireRedis, string? RedisUrl);

internal static class AuthLibraryOptionsValidator
{
    private const int MaxAccessTokenLifetimeMinutes = 60;
    private const int MaxRefreshTokenLifetimeDays = 90;

    public static ValidatedStartupSettings Validate(IConfiguration config)
    {
        var jwt = BindRequiredSection<JwtSettings>(config, "JwtSettings");
        var security = BindRequiredSection<SecuritySettings>(config, "SecuritySettings");
        var mail = BindRequiredSection<MailSettings>(config, "MailService");
        var auth = BindRequiredSection<AuthSettings>(config, "AuthSettings");
        var template = BindRequiredSection<TemplateSettings>(config, "TemplateSettings");
        var refreshToken = BindOptionalSection<RefreshTokenSettings>(config, "RefreshTokenSettings");
        var rateLimit = BindOptionalSection<RateLimitSettings>(config, "RateLimit");
        var google = BindOptionalSection<GoogleAuthSettings>(config, "GoogleAuth");

        ValidateJwt(jwt);
        ValidateSecurity(security);
        ValidateMail(mail);
        ValidateAuth(auth);
        ValidateTemplate(template);
        ValidateRefreshToken(refreshToken);
        ValidateRateLimit(rateLimit);
        ValidateGoogle(google);

        var redisUrl = config["Redis:Url"];
        if (rateLimit.RequireRedis && string.IsNullOrWhiteSpace(redisUrl))
        {
            throw new InvalidOperationException("RateLimit:RequireRedis e true ma Redis:Url non e configurato.");
        }

        return new ValidatedStartupSettings(rateLimit.RequireRedis, redisUrl);
    }

    private static T BindRequiredSection<T>(IConfiguration config, string sectionName) where T : new()
    {
        var section = config.GetSection(sectionName);
        if (!section.Exists())
        {
            throw new InvalidOperationException($"Sezione di configurazione mancante: {sectionName}");
        }

        return section.Get<T>() ?? new T();
    }

    private static T BindOptionalSection<T>(IConfiguration config, string sectionName) where T : new()
    {
        var section = config.GetSection(sectionName);
        if (!section.Exists())
        {
            return new T();
        }

        return section.Get<T>() ?? new T();
    }

    private static void ValidateJwt(JwtSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Key))
        {
            throw new InvalidOperationException("JwtSettings:Key non configurato.");
        }

        if (Encoding.UTF8.GetByteCount(settings.Key) < 32)
        {
            throw new InvalidOperationException("JwtSettings:Key deve essere almeno 32 byte.");
        }

        if (string.IsNullOrWhiteSpace(settings.Issuer))
        {
            throw new InvalidOperationException("JwtSettings:Issuer non configurato.");
        }

        if (string.IsNullOrWhiteSpace(settings.Audience))
        {
            throw new InvalidOperationException("JwtSettings:Audience non configurato.");
        }

        if (settings.AccessTokenLifetimeMinutes <= 0)
        {
            throw new InvalidOperationException("JwtSettings:AccessTokenLifetimeMinutes deve essere maggiore di 0.");
        }

        if (settings.AccessTokenLifetimeMinutes > MaxAccessTokenLifetimeMinutes)
        {
            throw new InvalidOperationException($"JwtSettings:AccessTokenLifetimeMinutes deve essere <= {MaxAccessTokenLifetimeMinutes}.");
        }
    }

    private static void ValidateSecurity(SecuritySettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Pepper))
        {
            throw new InvalidOperationException("SecuritySettings:Pepper non configurato.");
        }
    }

    private static void ValidateMail(MailSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.AppMail))
        {
            throw new InvalidOperationException("MailService:AppMail non configurato.");
        }

        if (!TryParseMail(settings.AppMail))
        {
            throw new InvalidOperationException("MailService:AppMail non valido.");
        }

        if (string.IsNullOrWhiteSpace(settings.Host))
        {
            throw new InvalidOperationException("MailService:Host non configurato.");
        }

        if (settings.Port is <= 0 or > 65535)
        {
            throw new InvalidOperationException("MailService:Port deve essere compreso tra 1 e 65535.");
        }

        if (string.IsNullOrWhiteSpace(settings.SenderName))
        {
            throw new InvalidOperationException("MailService:SenderName non configurato.");
        }

        if (settings.TimeoutSeconds <= 0)
        {
            throw new InvalidOperationException("MailService:TimeoutSeconds deve essere maggiore di 0.");
        }

        if (settings.RetryCount < 0)
        {
            throw new InvalidOperationException("MailService:RetryCount non puo essere negativo.");
        }

        if (settings.RetryDelayMilliseconds < 0)
        {
            throw new InvalidOperationException("MailService:RetryDelayMilliseconds non puo essere negativo.");
        }
    }

    private static void ValidateAuth(AuthSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.FrontendUrl))
        {
            throw new InvalidOperationException("AuthSettings:FrontendUrl non configurato.");
        }

        if (!Uri.TryCreate(settings.FrontendUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException("AuthSettings:FrontendUrl non valido.");
        }

        var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isLocalLoopback = uri.IsLoopback;
        if (!isHttps && !isLocalLoopback)
        {
            throw new InvalidOperationException("AuthSettings:FrontendUrl deve usare HTTPS (HTTP consentito solo in loopback locale).");
        }
    }

    private static void ValidateTemplate(TemplateSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.BasePath))
        {
            throw new InvalidOperationException("TemplateSettings:BasePath non configurato.");
        }
    }

    private static void ValidateRefreshToken(RefreshTokenSettings settings)
    {
        if (settings.RefreshTokenLifetimeDays <= 0)
        {
            throw new InvalidOperationException("RefreshTokenSettings:RefreshTokenLifetimeDays deve essere maggiore di 0.");
        }

        if (settings.RefreshTokenLifetimeDays > MaxRefreshTokenLifetimeDays)
        {
            throw new InvalidOperationException($"RefreshTokenSettings:RefreshTokenLifetimeDays deve essere <= {MaxRefreshTokenLifetimeDays}.");
        }
    }

    private static void ValidateRateLimit(RateLimitSettings settings)
    {
        if (settings.Rules == null)
        {
            throw new InvalidOperationException("RateLimit:Rules non puo essere null.");
        }

        foreach (var (ruleName, rule) in settings.Rules)
        {
            if (!System.Enum.TryParse<RateLimitRequestType>(ruleName, ignoreCase: true, out _))
            {
                throw new InvalidOperationException($"RateLimit:Rules contiene tipo non supportato: {ruleName}");
            }

            if (rule == null)
            {
                throw new InvalidOperationException($"RateLimit:Rules:{ruleName} non valido.");
            }

            if (rule.MaxUserAttempts <= 0)
            {
                throw new InvalidOperationException($"RateLimit:Rules:{ruleName}:MaxUserAttempts deve essere maggiore di 0.");
            }

            if (rule.MaxIpAttempts <= 0)
            {
                throw new InvalidOperationException($"RateLimit:Rules:{ruleName}:MaxIpAttempts deve essere maggiore di 0.");
            }

            if (rule.AttemptWindow <= TimeSpan.Zero)
            {
                throw new InvalidOperationException($"RateLimit:Rules:{ruleName}:AttemptWindow deve essere maggiore di 0.");
            }

            if (rule.LockDuration <= TimeSpan.Zero)
            {
                throw new InvalidOperationException($"RateLimit:Rules:{ruleName}:LockDuration deve essere maggiore di 0.");
            }
        }

        var mergedRules = RateLimitService.BuildConfig(settings);
        foreach (var requestType in System.Enum.GetValues<RateLimitRequestType>())
        {
            if (!mergedRules.ContainsKey(requestType))
            {
                throw new InvalidOperationException($"RateLimit:Rules configurazione mancante per {requestType}.");
            }
        }

        if (settings.TrustedProxyIps == null)
        {
            throw new InvalidOperationException("RateLimit:TrustedProxyIps non puo essere null.");
        }

        foreach (var proxyIp in settings.TrustedProxyIps)
        {
            if (string.IsNullOrWhiteSpace(proxyIp))
            {
                continue;
            }

            if (!IPAddress.TryParse(proxyIp, out _))
            {
                throw new InvalidOperationException($"RateLimit:TrustedProxyIps contiene IP non valido: {proxyIp}");
            }
        }
    }

    private static void ValidateGoogle(GoogleAuthSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.AllowedHostedDomain))
        {
            return;
        }

        if (settings.AllowedHostedDomain.Contains(' '))
        {
            throw new InvalidOperationException("GoogleAuth:AllowedHostedDomain non valido.");
        }
    }

    private static bool TryParseMail(string email)
    {
        try
        {
            var parsed = new MailAddress(email);
            return string.Equals(parsed.Address, email, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
