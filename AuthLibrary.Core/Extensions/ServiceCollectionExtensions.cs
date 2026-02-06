using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
        var startupSettings = AuthLibraryOptionsValidator.Validate(config);

        services.Configure<JwtSettings>(config.GetSection("JwtSettings"));
        services.Configure<SecuritySettings>(config.GetSection("SecuritySettings"));
        services.Configure<MailSettings>(config.GetSection("MailService"));
        services.Configure<AuthSettings>(config.GetSection("AuthSettings"));
        services.Configure<TemplateSettings>(config.GetSection("TemplateSettings"));
        services.Configure<RateLimitSettings>(config.GetSection("RateLimit"));
        services.Configure<RefreshTokenSettings>(config.GetSection("RefreshTokenSettings"));
        services.Configure<GoogleAuthSettings>(config.GetSection("GoogleAuth"));

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
        services.AddScoped<AuthRuntime<TUser>>(sp =>
        {
            var repository = sp.GetRequiredService<IAuthRepository<TUser>>();
            var securitySettings = sp.GetRequiredService<IOptions<SecuritySettings>>().Value;
            var mailService = sp.GetRequiredService<IMailService>();
            var tokenService = sp.GetRequiredService<ITokenService<TUser>>();
            var rateLimitService = sp.GetRequiredService<IRateLimitService>();
            var templateService = sp.GetRequiredService<IMailTemplateService>();
            var authSettings = sp.GetRequiredService<IOptions<AuthSettings>>().Value;
            var mailSettings = sp.GetRequiredService<IOptions<MailSettings>>().Value;
            var logger = sp.GetRequiredService<ILogger<AuthService<TUser>>>();
            var passwordValidator = sp.GetRequiredService<IPasswordValidator>();
            var externalTokenValidator = sp.GetRequiredService<IExternalTokenValidator>();
            var externalUserFactory = sp.GetService<IExternalUserFactory<TUser>>();

            return new AuthRuntime<TUser>(
                repository,
                securitySettings.Pepper,
                mailService,
                tokenService,
                rateLimitService,
                templateService,
                authSettings,
                mailSettings,
                logger,
                passwordValidator,
                externalTokenValidator,
                externalUserFactory);
        });

        services.AddScoped<LoginService<TUser>>();
        services.AddScoped<RegisterService<TUser>>();
        services.AddScoped<EmailVerificationService<TUser>>();
        services.AddScoped<PasswordService<TUser>>();
        services.AddScoped<ExternalLoginService<TUser>>();

        services.AddScoped<ILoginService<TUser>>(sp => sp.GetRequiredService<LoginService<TUser>>());
        services.AddScoped<IRegisterService<TUser>>(sp => sp.GetRequiredService<RegisterService<TUser>>());
        services.AddScoped<IEmailVerificationService<TUser>>(sp => sp.GetRequiredService<EmailVerificationService<TUser>>());
        services.AddScoped<IPasswordFlowService<TUser>>(sp => sp.GetRequiredService<PasswordService<TUser>>());
        services.AddScoped<IExternalLoginService<TUser>>(sp => sp.GetRequiredService<ExternalLoginService<TUser>>());
        services.AddScoped<IAuthService<TUser>, AuthService<TUser>>();

        // Always add MemoryCache (used as fallback if Redis fails)
        services.AddMemoryCache();

        // Redis with automatic in-memory fallback
        var redisUrl = startupSettings.RedisUrl;
        var requireRedis = startupSettings.RequireRedis;
        if (requireRedis && string.IsNullOrWhiteSpace(redisUrl))
        {
            throw new InvalidOperationException("RateLimit:RequireRedis e true ma Redis:Url non e configurato.");
        }

        if (!string.IsNullOrWhiteSpace(redisUrl))
        {
            if (requireRedis)
            {
                try
                {
                    var multiplexer = ConnectionMultiplexer.Connect(redisUrl);
                    if (multiplexer?.IsConnected != true)
                    {
                        throw new InvalidOperationException("RateLimit:RequireRedis e true ma Redis non e raggiungibile.");
                    }

                    var ping = multiplexer.GetDatabase().Ping();
                    if (ping <= TimeSpan.Zero)
                    {
                        throw new InvalidOperationException("RateLimit:RequireRedis e true ma Redis non risponde al ping.");
                    }

                    services.AddSingleton(new RedisConnectionHolder(multiplexer, true));
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Redis e richiesto ma non disponibile.", ex);
                }
            }
            else
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
                    }

                    return new RedisConnectionHolder(multiplexer, false);
                });
            }

            services.AddScoped<IRedisService>(sp =>
            {
                var holder = sp.GetRequiredService<RedisConnectionHolder>();
                if (holder.Multiplexer?.IsConnected == true)
                {
                    return new RedisService(holder.Multiplexer);
                }

                if (holder.RequireRedis)
                {
                    throw new InvalidOperationException("Redis e richiesto ma non disponibile.");
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
