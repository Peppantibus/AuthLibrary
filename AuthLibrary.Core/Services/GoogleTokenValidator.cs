using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Models.Dto.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AuthLibrary.Services;

public class GoogleTokenValidator : IExternalTokenValidator
{
    private static readonly string[] ValidIssuers = new[]
    {
        "https://accounts.google.com",
        "accounts.google.com"
    };

    private readonly GoogleAuthSettings _settings;
    private readonly ILogger<GoogleTokenValidator> _logger;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

    public GoogleTokenValidator(IOptions<GoogleAuthSettings> settings, ILogger<GoogleTokenValidator> logger)
    {
        _settings = settings.Value;
        _logger = logger;

        var documentRetriever = new HttpDocumentRetriever { RequireHttps = true };
        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "https://accounts.google.com/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            documentRetriever);
    }

    public async Task<ExternalUserInfo> ValidateGoogleIdToken(string idToken, string? expectedNonce = null)
    {
        if (string.IsNullOrWhiteSpace(idToken))
        {
            throw new InvalidOperationException("token non valido");
        }

        if (string.IsNullOrWhiteSpace(_settings.ClientId))
        {
            throw new InvalidOperationException("GoogleAuth:ClientId non configurato.");
        }

        OpenIdConnectConfiguration config;
        try
        {
            config = await _configurationManager.GetConfigurationAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossibile recuperare la configurazione OpenID di Google");
            throw new InvalidOperationException("token non valido");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = ValidIssuers,
            ValidateAudience = true,
            ValidAudience = _settings.ClientId,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            ClockSkew = TimeSpan.FromMinutes(2)
        };

        ClaimsPrincipal principal;
        SecurityToken validatedToken;
        try
        {
            var handler = new JwtSecurityTokenHandler();
            principal = handler.ValidateToken(idToken, validationParameters, out validatedToken);
        }
        catch (Exception ex) when (ex is SecurityTokenException || ex is ArgumentException)
        {
            _logger.LogWarning(ex, "Token Google non valido");
            throw new InvalidOperationException("token non valido");
        }

        var email = principal.FindFirst("email")?.Value;
        var emailVerifiedRaw = principal.FindFirst("email_verified")?.Value;
        var subject = principal.FindFirst("sub")?.Value;
        var nonce = principal.FindFirst("nonce")?.Value;
        var name = principal.FindFirst("name")?.Value;
        var givenName = principal.FindFirst("given_name")?.Value;
        var familyName = principal.FindFirst("family_name")?.Value;
        var hostedDomain = principal.FindFirst("hd")?.Value;

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(subject))
        {
            throw new InvalidOperationException("token non valido");
        }

        var emailVerified = string.Equals(emailVerifiedRaw, "true", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(emailVerifiedRaw, "1", StringComparison.OrdinalIgnoreCase);

        if (!emailVerified)
        {
            throw new InvalidOperationException("email non verificata");
        }

        if (!string.IsNullOrWhiteSpace(expectedNonce) &&
            !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("nonce non valido");
        }

        if (validatedToken.ValidTo <= DateTime.UtcNow)
        {
            throw new InvalidOperationException("token non valido");
        }

        if (!string.IsNullOrWhiteSpace(_settings.AllowedHostedDomain))
        {
            if (!string.Equals(hostedDomain, _settings.AllowedHostedDomain, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("dominio non consentito");
            }
        }

        return new ExternalUserInfo
        {
            Subject = subject,
            Email = email,
            EmailVerified = emailVerified,
            Nonce = nonce,
            ExpiresAtUtc = validatedToken.ValidTo,
            Name = name,
            GivenName = givenName,
            FamilyName = familyName
        };
    }
}
