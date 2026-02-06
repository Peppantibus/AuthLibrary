using AuthLibrary.Configuration;
using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace AuthLibrary.Services;

public class RateLimitService : IRateLimitService
{
    private const int MaxIdentifierLength = 256;
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
        _config = MergeWithDefaults(config);
        _trustedProxyIps = BuildTrustedProxySet(trustedProxyIps);
    }

    /// <summary>
    /// Gets the client IP address, supporting X-Forwarded-For for proxy/load balancer scenarios.
    /// SECURITY: In production, ensure your proxy is trusted and properly configured.
    /// </summary>
    private string GetClientIP(string identifier)
    {
        var safeIdentifier = NormalizeIdentifier(identifier);
        var context = _contextAccessor.HttpContext;
        if (context == null)
        {
            // No HttpContext (background/non-HTTP usage); scope to identifier to avoid global lockouts.
            return $"unknown-ip:{safeIdentifier}";
        }

        var remoteIp = NormalizeIp(context.Connection.RemoteIpAddress?.ToString());
        if (remoteIp == null)
        {
            return "unknown-ip";
        }

        // Parse X-Forwarded-For only when the request originates from a trusted proxy.
        // We walk right-to-left and pick the first non-trusted valid IP to avoid spoofed
        // leftmost values when clients inject their own header and proxies append to it.
        if (_trustedProxyIps.Contains(remoteIp))
        {
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                var candidates = forwardedFor
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(NormalizeIp)
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Cast<string>()
                    .ToArray();

                for (var i = candidates.Length - 1; i >= 0; i--)
                {
                    if (!_trustedProxyIps.Contains(candidates[i]))
                    {
                        return candidates[i];
                    }
                }
            }
        }

        return remoteIp;
    }

    private static HashSet<string> BuildTrustedProxySet(IEnumerable<string>? trustedProxyIps)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (trustedProxyIps == null)
        {
            return set;
        }

        foreach (var proxy in trustedProxyIps)
        {
            var normalized = NormalizeIp(proxy);
            if (!string.IsNullOrEmpty(normalized))
            {
                set.Add(normalized);
            }
        }

        return set;
    }

    private static string? NormalizeIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return null;
        }

        return IPAddress.TryParse(ip.Trim(), out var parsed)
            ? parsed.ToString()
            : null;
    }

    private static string NormalizeIdentifier(string? identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return string.Empty;
        }

        var normalized = identifier.Trim();
        return normalized.Length <= MaxIdentifierLength
            ? normalized
            : normalized[..MaxIdentifierLength];
    }

    public async Task<bool> IsBlocked(RateLimitRequestType type, string identifier)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        var ip = GetClientIP(normalizedIdentifier);
        var hasIdentifier = !string.IsNullOrWhiteSpace(normalizedIdentifier);

        string ipLockKey = $"rl:lock:{type}:ip:{ip}";
        var ipBlocked = await _redisService.GetValue(ipLockKey) != null;
        if (!hasIdentifier)
        {
            return ipBlocked;
        }

        string userLockKey = $"rl:lock:{type}:{normalizedIdentifier}";
        var userBlocked = await _redisService.GetValue(userLockKey) != null;

        return ipBlocked || userBlocked;
    }

    public async Task<bool> RegisterAttempted(RateLimitRequestType type, string idenfier)
    {
        _config.TryGetValue(type, out var configuration);

        if (configuration == null) {
            throw new InvalidOperationException("enum non registrato");
        }

        var normalizedIdentifier = NormalizeIdentifier(idenfier);
        var ip = GetClientIP(normalizedIdentifier);
        var hasIdentifier = !string.IsNullOrWhiteSpace(normalizedIdentifier);

        string ipAttemptKey = $"rl:attempt:{type}:ip:{ip}";
        var ipAttempts = await _redisService.Increment(ipAttemptKey, 1);
        double identifierAttempts = 0;

        if (ipAttempts == 1)
        {
             await _redisService.Expire(ipAttemptKey, configuration.AttemptWindow);
        }

        if (hasIdentifier)
        {
            string identifierAttemptKey = $"rl:attempt:{type}:{normalizedIdentifier}";
            identifierAttempts = await _redisService.Increment(identifierAttemptKey, 1);

            if (identifierAttempts == 1)
            {
                 await _redisService.Expire(identifierAttemptKey, configuration.AttemptWindow);
            }
        }

        if (ipAttempts > configuration.MaxIpAttempts)
        {
            await _redisService.SetValue($"rl:lock:{type}:ip:{ip}", "1", configuration.LockDuration);
            return true;
        }

        if (hasIdentifier && identifierAttempts > configuration.MaxUserAttempts)
        {
            await _redisService.SetValue($"rl:lock:{type}:{normalizedIdentifier}", "1", configuration.LockDuration);
            return true;
        }

        return false;
    }

    public async Task Reset(RateLimitRequestType type, string identifier)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        var hasIdentifier = !string.IsNullOrWhiteSpace(normalizedIdentifier);

        // Preserve IP counters across successful authentications to avoid brute-force bypass
        // via alternating successful/failed attempts from the same source.
        if (!hasIdentifier)
        {
            return;
        }

        await _redisService.Remove($"rl:attempt:{type}:{normalizedIdentifier}");
        await _redisService.Remove($"rl:lock:{type}:{normalizedIdentifier}");
    }

    public async Task<bool> IsInCooldown(RateLimitRequestType type, string identifier)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        string key = $"rl:cooldown:{type}:{normalizedIdentifier}";
        return await _redisService.GetValue(key) != null;
    }

    public async Task StartCooldown(RateLimitRequestType type, string identifier, TimeSpan duration)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        string key = $"rl:cooldown:{type}:{normalizedIdentifier}";
        await _redisService.SetValue(key, "1", duration);
    }

    public async Task<bool> TryStartCooldown(RateLimitRequestType type, string identifier, TimeSpan duration)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        string key = $"rl:cooldown:{type}:{normalizedIdentifier}";
        return await _redisService.TrySetValue(key, "1", duration);
    }

    public async Task ClearCooldown(RateLimitRequestType type, string identifier)
    {
        var normalizedIdentifier = NormalizeIdentifier(identifier);
        string key = $"rl:cooldown:{type}:{normalizedIdentifier}";
        await _redisService.Remove(key);
    }

    public static Dictionary<RateLimitRequestType, RateLimitConfiguration> BuildConfig(RateLimitSettings? settings = null)
    {
        var config = BuildDefaultConfig();
        if (settings?.Rules != null && settings.Rules.Count > 0)
        {
            foreach (var entry in settings.Rules)
            {
                if (System.Enum.TryParse<RateLimitRequestType>(entry.Key, ignoreCase: true, out var type))
                {
                    config[type] = entry.Value;
                }
            }
        }

        return config;
    }

    private static Dictionary<RateLimitRequestType, RateLimitConfiguration> MergeWithDefaults(
        Dictionary<RateLimitRequestType, RateLimitConfiguration>? config)
    {
        var merged = BuildDefaultConfig();
        if (config == null)
        {
            return merged;
        }

        foreach (var entry in config)
        {
            if (entry.Value != null)
            {
                merged[entry.Key] = entry.Value;
            }
        }

        return merged;
    }

    private static Dictionary<RateLimitRequestType, RateLimitConfiguration> BuildDefaultConfig()
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
            },
            {
                RateLimitRequestType.ExternalLogin,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 5,
                    MaxIpAttempts = 20,
                    AttemptWindow = TimeSpan.FromMinutes(15),
                    LockDuration = TimeSpan.FromMinutes(5)
                }
            },
            {
                RateLimitRequestType.RefreshToken,
                new RateLimitConfiguration
                {
                    MaxUserAttempts = 30,
                    MaxIpAttempts = 60,
                    AttemptWindow = TimeSpan.FromMinutes(15),
                    LockDuration = TimeSpan.FromMinutes(5)
                }
            }
        };
    }
}
