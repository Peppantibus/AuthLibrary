using Chat.AuthLibrary.Configuration;
using Chat.AuthLibrary.Enum;
using Chat.AuthLibrary.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Chat.AuthLibrary.Services;

public class RateLimitService : IRateLimitService
{
    private readonly IRedisService _redisService;
    private readonly IHttpContextAccessor _contextAccessor;
    private readonly Dictionary<RateLimitRequestType, RateLimitConfiguration> _config;
    private readonly HashSet<string> _trustedProxyIps;

    public RateLimitService(
        IRedisService redisService,
        IHttpContextAccessor contextAccessor,
        Dictionary<RateLimitRequestType, RateLimitConfiguration>? config = null,
        IEnumerable<string>? trustedProxyIps = null)
    {
        _redisService = redisService;
        _contextAccessor = contextAccessor;
        _config = config ?? BuildConfig();
        _trustedProxyIps = trustedProxyIps == null
            ? new HashSet<string>()
            : new HashSet<string>(trustedProxyIps);
    }

    /// <summary>
    /// Gets the client IP address, supporting X-Forwarded-For for proxy/load balancer scenarios.
    /// SECURITY: In production, ensure your proxy is trusted and properly configured.
    /// </summary>
    private string GetClientIP(string identifier)
    {
        var context = _contextAccessor.HttpContext;
        if (context == null)
        {
            // No HttpContext (background/non-HTTP usage); scope to identifier to avoid global lockouts.
            return $"unknown-ip:{identifier}";
        }

        // Check X-Forwarded-For header only if request came from a trusted proxy
        var remoteIp = context.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrEmpty(remoteIp) && _trustedProxyIps.Contains(remoteIp))
        {
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2...
                // Take the first one (leftmost) as the original client IP
                var clientIp = forwardedFor.Split(',')[0].Trim();
                if (!string.IsNullOrEmpty(clientIp))
                {
                    return clientIp;
                }
            }
        }

        // Fall back to RemoteIpAddress
        return string.IsNullOrEmpty(remoteIp) ? "unknown-ip" : remoteIp;
    }

    public async Task<bool> IsBlocked(RateLimitRequestType type, string identifier)
    {
        var ip = GetClientIP(identifier);

        string ipLockKey = $"rl:lock:{type}:ip:{ip}";
        string userLockKey = $"rl:lock:{type}:{identifier}";

        var ipBlocked = await _redisService.GetValue(ipLockKey) != null;
        var userBlocked = await _redisService.GetValue(userLockKey) != null;

        return ipBlocked || userBlocked;
    }

    public async Task<bool> RegisterAttempted(RateLimitRequestType type, string idenfier)
    {
        _config.TryGetValue(type, out var configuration);

        if (configuration == null) {
            throw new InvalidOperationException("enum non registrato");
        }

        var ip = GetClientIP(idenfier);

        string ipAttemptKey = $"rl:attempt:{type}:ip:{ip}";
        string identifierAttemptKey = $"rl:attempt:{type}:{idenfier}";

        var ipAttempts = await _redisService.Increment(ipAttemptKey, 1);
        var identifierAttempts = await _redisService.Increment(identifierAttemptKey, 1);

        if (ipAttempts == 1)
        {
             await _redisService.Expire(ipAttemptKey, configuration.AttemptWindow);
        }
        
        if (identifierAttempts == 1)
        {
             await _redisService.Expire(identifierAttemptKey, configuration.AttemptWindow);
        }

        if (ipAttempts > configuration.MaxIpAttempts)
        {
            await _redisService.SetValue($"rl:lock:{type}:ip:{ip}", "1", configuration.LockDuration);
            return true;
        }

        if (identifierAttempts > configuration.MaxUserAttempts)
        {
            await _redisService.SetValue($"rl:lock:{type}:{idenfier}", "1", configuration.LockDuration);
            return true;
        }

        return false;
    }

    public async Task Reset(RateLimitRequestType type, string identifier)
    {
        var ip = GetClientIP(identifier);

        await _redisService.Remove($"rl:attempt:{type}:ip:{ip}");
        await _redisService.Remove($"rl:attempt:{type}:{identifier}");
    }

    public async Task<bool> IsInCooldown(RateLimitRequestType type, string identifier)
    {
        string key = $"rl:cooldown:{type}:{identifier}";
        return await _redisService.GetValue(key) != null;
    }

    public async Task StartCooldown(RateLimitRequestType type, string identifier, TimeSpan duration)
    {
        string key = $"rl:cooldown:{type}:{identifier}";
        await _redisService.SetValue(key, "1", duration);
    }

    private static Dictionary<RateLimitRequestType, RateLimitConfiguration> BuildConfig()
    {
        return new()
        {
            {
                RateLimitRequestType.Login,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 5,
                    MaxIpAttempts = 20,
                    AttemptWindow = TimeSpan.FromMinutes(15),
                    LockDuration = TimeSpan.FromMinutes(5)
                }
            },
            {
                RateLimitRequestType.Register,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 3,
                    MaxIpAttempts = 10,
                    AttemptWindow = TimeSpan.FromMinutes(30),
                    LockDuration = TimeSpan.FromMinutes(10)
                }
            },
            {
                RateLimitRequestType.VerifyEmail,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 5,
                    MaxIpAttempts = 15,
                    AttemptWindow = TimeSpan.FromHours(1),
                    LockDuration = TimeSpan.FromMinutes(15)
                }
            },
            {
                RateLimitRequestType.ResetPassword,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 3,
                    MaxIpAttempts = 10,
                    AttemptWindow = TimeSpan.FromMinutes(30),
                    LockDuration = TimeSpan.FromMinutes(15)
                }
            }
        };
    }
}
