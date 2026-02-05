using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace AuthLibrary.Extensions;

public static class ServiceCollectionExtensions
{
    private sealed class RedisConnectionHolder
    {
        public IConnectionMultiplexer? Multiplexer { get; }
        public bool RequireRedis { get; }

        public RedisConnectionHolder(IConnectionMultiplexer? multiplexer, bool requireRedis)
        {
            Multiplexer = multiplexer;
            RequireRedis = requireRedis;
        }
    }

    public static IServiceCollection AddAuthLibrary<TUser>(this IServiceCollection services, IConfiguration config) 
        where TUser : class, IAuthUser
    {
        services.Configure<JwtSettings>(config.GetSection("JwtSettings"));
        services.Configure<SecuritySettings>(config.GetSection("SecuritySettings"));
        services.Configure<MailSettings>(config.GetSection("MailService"));
        services.Configure<AuthSettings>(config.GetSection("AuthSettings"));
        services.Configure<TemplateSettings>(config.GetSection("TemplateSettings"));
        services.Configure<RateLimitSettings>(config.GetSection("RateLimit"));
        services.Configure<RefreshTokenSettings>(config.GetSection("RefreshTokenSettings"));
        services.Configure<GoogleAuthSettings>(config.GetSection("GoogleAuth"));

        services.AddScoped<IAuthService<TUser>, AuthService<TUser>>();
        services.AddScoped<ITokenService<TUser>, TokenService<TUser>>();
        services.AddScoped<IMailService, MailService>();
        services.AddScoped<IMailTemplateService, MailTemplateService>();
        services.AddScoped<IExternalTokenValidator, GoogleTokenValidator>();
        services.AddScoped<IRateLimitService>(sp =>
        {
            var redis = sp.GetRequiredService<IRedisService>();
            var http = sp.GetRequiredService<IHttpContextAccessor>();
            var rateLimitSettings = sp.GetRequiredService<IOptions<RateLimitSettings>>().Value;
            return new RateLimitService(
                redis,
                http,
                RateLimitService.BuildConfig(rateLimitSettings),
                rateLimitSettings.TrustedProxyIps);
        });
        services.AddScoped<IPasswordValidator, DefaultPasswordValidator>();
        
        // Always add MemoryCache (used as fallback if Redis fails)
        services.AddMemoryCache();
        
        // Redis with automatic in-memory fallback
        var redisUrl = config["Redis:Url"];
        var requireRedis = config.GetValue<bool>("RateLimit:RequireRedis");
        if (!string.IsNullOrEmpty(redisUrl))
        {
            // Try to use Redis, but fallback to memory cache if it fails
            services.AddSingleton(sp =>
            {
                IConnectionMultiplexer? multiplexer = null;
                try
                {
                    multiplexer = ConnectionMultiplexer.Connect(redisUrl);
                }
                catch (Exception)
                {
                    if (requireRedis)
                    {
                        throw new InvalidOperationException("Redis è richiesto ma non disponibile.");
                    }
                }
                return new RedisConnectionHolder(multiplexer, requireRedis);
            });
            
            services.AddScoped<IRedisService>(sp =>
            {
                var holder = sp.GetRequiredService<RedisConnectionHolder>();
                if (holder.Multiplexer?.IsConnected == true)
                {
                    return new RedisService(holder.Multiplexer);
                }

                if (holder.RequireRedis)
                {
                    throw new InvalidOperationException("Redis è richiesto ma non disponibile.");
                }

                // Fallback to in-memory cache
                var logger = sp.GetRequiredService<ILogger<RedisService>>();
                logger.LogWarning("Redis non disponibile, uso cache in-memory per rate limiting.");
                var memoryCache = sp.GetRequiredService<IMemoryCache>();
                return new InMemoryCacheService(memoryCache);
            });
        }
        else
        {
            // No Redis URL configured, use in-memory cache only
            services.AddScoped<IRedisService, InMemoryCacheService>();
        }

        return services;
    }
}
