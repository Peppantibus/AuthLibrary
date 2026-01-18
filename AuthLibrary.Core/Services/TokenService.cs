using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthLibrary.Services;

public class TokenService<TUser> : ITokenService<TUser> where TUser : class, IAuthUser
{
    private readonly JwtSettings _jwt;
    private readonly ILogger<TokenService<TUser>> _logger;
    private readonly IAuthRepository<TUser> _repository;
    private readonly RefreshTokenSettings _refreshTokenSettings;

    public TokenService(
        IOptions<JwtSettings> jwtSettings,
        ILogger<TokenService<TUser>> logger,
        IAuthRepository<TUser> repository,
        IOptions<RefreshTokenSettings> refreshTokenSettings)
    {
        _jwt = jwtSettings.Value;
        _logger = logger;
        _repository = repository;
        _refreshTokenSettings = refreshTokenSettings.Value;
        
        // SECURITY: Validate JWT key configuration
        ValidateJwtConfiguration();
    }

    /// <summary>
    /// Validates JWT configuration at startup to prevent runtime security issues.
    /// </summary>
    private void ValidateJwtConfiguration()
    {
        if (string.IsNullOrEmpty(_jwt.Key))
        {
            throw new InvalidOperationException("JWT Key is not configured. Set JwtSettings:Key in your configuration.");
        }

        // HMAC-SHA256 requires minimum 32 bytes (256 bits) for security
        var keyBytes = Encoding.UTF8.GetBytes(_jwt.Key);
        if (keyBytes.Length < 32)
        {
            _logger.LogWarning("JWT Key is less than 32 bytes ({Length} bytes). This is below recommended security threshold.", keyBytes.Length);
            throw new InvalidOperationException($"JWT Key must be at least 32 bytes (256 bits) for HMAC-SHA256. Current key is {keyBytes.Length} bytes.");
        }

        if (string.IsNullOrEmpty(_jwt.Issuer))
        {
            _logger.LogWarning("JWT Issuer is not configured. This may cause token validation issues.");
        }

        if (string.IsNullOrEmpty(_jwt.Audience))
        {
            _logger.LogWarning("JWT Audience is not configured. This may cause token validation issues.");
        }

        if (_jwt.AccessTokenLifetimeMinutes <= 0)
        {
            throw new InvalidOperationException("JWT AccessTokenLifetimeMinutes must be greater than 0.");
        }

        _logger.LogInformation("JWT configuration validated successfully. Key length: {KeyLength} bytes, Token lifetime: {Lifetime} minutes", 
            keyBytes.Length, _jwt.AccessTokenLifetimeMinutes);
    }

    private static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    public async Task<RefreshTokenDto> RefreshToken(string token)
    {
        var result = await ValidateRefreshToken(token);
        var userId = result.UserId;
        
        var queryUser = await _repository.GetUserByIdAsync(userId);

        if (queryUser == null)
        {
            throw new InvalidOperationException("nessun utente trovato");
        }

        var accessToken = GenerateAccessToken(queryUser);

        return new RefreshTokenDto
        {
            NewRefreshToken = result.PlainToken,
            RefreshTokenExpiresAt = result.ExpiresAt,
            AccessToken = accessToken,
            User = new UserDto
            {
                Id = queryUser.Id,
                Username = queryUser.Username,
                Name = queryUser.Name,
                LastName = queryUser.LastName,
            }
        };

    }

    public async Task<Result<RefreshTokenDto>> TryRefreshToken(string token)
    {
        try
        {
            var dto = await RefreshToken(token);
            return Result.Ok(dto);
        }
        catch (InvalidOperationException)
        {
            _logger.LogWarning("Refresh token non valido");
            return Result.Fail<RefreshTokenDto>("token non valido");
        }
        catch (Exception)
        {
            _logger.LogWarning("Errore durante il refresh token");
            return Result.Fail<RefreshTokenDto>("errore durante il refresh token");
        }
    }

    public string GenerateRefreshToken() 
    { 
        var randomNumber = RandomNumberGenerator.GetBytes(64); 
        return Convert.ToBase64String(randomNumber); 
    }

    public async Task<RefreshTokenIssueResult> CreateRefreshToken(TUser user)
    {
        var token = GenerateRefreshToken();
        var tokenHash = HashToken(token);

        var entity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(_refreshTokenSettings.RefreshTokenLifetimeDays),
            RevokedAt = null,
            ReplacedByToken = null
        };
        
        await _repository.AddRefreshTokenAsync(entity);
        await _repository.SaveChangesAsync();

        return new RefreshTokenIssueResult
        {
            UserId = entity.UserId,
            PlainToken = token,
            ExpiresAt = entity.ExpiresAt
        };
    }

    public AccessTokenResult GenerateAccessToken(TUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim("email", user.Email),
            new Claim("type", "access"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var expires = DateTime.UtcNow.AddMinutes(_jwt.AccessTokenLifetimeMinutes);

        var token = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );

        return new AccessTokenResult
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            ExpiresInSeconds = _jwt.AccessTokenLifetimeMinutes * 60
        };
    }

    private async Task<RefreshTokenIssueResult> ValidateRefreshToken(string token)
    {
        var tokenHash = HashToken(token);
        var existingEntry = await _repository.GetRefreshTokenAsync(tokenHash);
        
        if (existingEntry == null)
        {
            throw new InvalidOperationException("token non valido");
        }

        if (existingEntry.ExpiresAt <= DateTime.UtcNow)
        {
            throw new InvalidOperationException("token non valido");
        }

        if (existingEntry.ReplacedByToken != null)
        {
             await _repository.RemoveRefreshTokensByUserIdAsync(existingEntry.UserId);
             await _repository.SaveChangesAsync();
            _logger.LogWarning("refresh token reuse rilevato: sessione invalidata");
            throw new InvalidOperationException("token non valido");
        }

        if (existingEntry.RevokedAt != null)
        {
            throw new InvalidOperationException("token non valido");
        }

        // Security: Invalidate tokens created before password change
        var user = await _repository.GetUserByIdAsync(existingEntry.UserId);
        if (user != null && user.PasswordUpdatedAt.HasValue)
        {
            if (existingEntry.CreatedAt < user.PasswordUpdatedAt.Value)
            {
                _logger.LogWarning("Token invalidato: creato prima del cambio password per utente {userId}", existingEntry.UserId);
                throw new InvalidOperationException("token non valido");
            }
        }

        return await UpdateRefreshToken(existingEntry);
    }

    private async Task<RefreshTokenIssueResult> UpdateRefreshToken(RefreshToken oldEntity)
    {
        if (oldEntity == null) { throw new InvalidOperationException("token non trovato"); }

        // SECURITY: Re-fetch token to check for concurrent modification (race condition protection)
        var currentState = await _repository.GetRefreshTokenAsync(oldEntity.TokenHash);
        if (currentState == null || currentState.RevokedAt != null || currentState.ReplacedByToken != null)
        {
            _logger.LogWarning("Race condition detected: token already rotated during request, userId={userId}", oldEntity.UserId);
            throw new InvalidOperationException("token non valido");
        }

        string newToken = GenerateRefreshToken();
        string newTokenHash = HashToken(newToken);
            
        oldEntity.RevokedAt = DateTime.UtcNow;
        oldEntity.ReplacedByToken = newTokenHash;

        await _repository.UpdateRefreshTokenAsync(oldEntity);

        var newEntity = new RefreshToken
        {
            UserId = oldEntity.UserId,
            TokenHash = newTokenHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(_refreshTokenSettings.RefreshTokenLifetimeDays)
        };

        await _repository.AddRefreshTokenAsync(newEntity);
        await _repository.SaveChangesAsync();

        return new RefreshTokenIssueResult
        {
            UserId = newEntity.UserId,
            PlainToken = newToken,
            ExpiresAt = newEntity.ExpiresAt
        };
    }
}
