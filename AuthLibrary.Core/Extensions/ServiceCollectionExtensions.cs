using Chat.AuthLibrary.Configuration;
using Chat.AuthLibrary.Interfaces;
using Chat.AuthLibrary.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Chat.AuthLibrary.Extensions;

public static class ServiceCollectionExtensions
{
    private sealed class RedisConnectionHolder
    {
        public IConnectionMultiplexer? Multiplexer { get; }

        public RedisConnectionHolder(IConnectionMultiplexer? multiplexer)
        {
            Multiplexer = multiplexer;
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

        services.AddScoped<IAuthService<TUser>, AuthService<TUser>>();
        services.AddScoped<ITokenService<TUser>, TokenService<TUser>>();
        services.AddScoped<IMailService, MailService>();
        services.AddScoped<IMailTemplateService, MailTemplateService>();
        services.AddScoped<IRateLimitService>(sp =>
        {
            var redis = sp.GetRequiredService<IRedisService>();
            var http = sp.GetRequiredService<IHttpContextAccessor>();
            var rateLimitSettings = sp.GetRequiredService<IOptions<RateLimitSettings>>().Value;
            return new RateLimitService(redis, http, RateLimitService.BuildConfig(rateLimitSettings));
        });
        services.AddScoped<IPasswordValidator, DefaultPasswordValidator>();
        
        // Always add MemoryCache (used as fallback if Redis fails)
        services.AddMemoryCache();
        
        // Redis with automatic in-memory fallback
        var redisUrl = config["Redis:Url"];
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
                    // Redis connection failed, will use in-memory fallback
                }
                return new RedisConnectionHolder(multiplexer);
            });
            
            services.AddScoped<IRedisService>(sp =>
            {
                var holder = sp.GetRequiredService<RedisConnectionHolder>();
                if (holder.Multiplexer?.IsConnected == true)
                {
                    return new RedisService(holder.Multiplexer);
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
