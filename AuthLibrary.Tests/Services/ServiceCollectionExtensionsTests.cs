using AuthLibrary.Extensions;
using AuthLibrary.Tests.Helpers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthLibrary.Tests.Services;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthLibrary_WithNoRedisUrl_RegistersInMemoryCacheService()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["RateLimit:RequireRedis"] = "false"
        });
        var services = new ServiceCollection();

        // Act
        services.AddAuthLibrary<TestUser>(config);
        var provider = services.BuildServiceProvider();

        // Assert
        var redis = provider.GetRequiredService<IRedisService>();
        redis.Should().BeOfType<InMemoryCacheService>();
    }

    [Fact]
    public void AddAuthLibrary_WithRequireRedisAndNoRedisUrl_Throws()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["RateLimit:RequireRedis"] = "true"
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*RateLimit:RequireRedis*");
    }

    [Fact]
    public void AddAuthLibrary_WithRequireRedisAndUnreachableRedis_ThrowsAtStartup()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["RateLimit:RequireRedis"] = "true",
            ["Redis:Url"] = "localhost:6399,abortConnect=true,connectTimeout=1000,syncTimeout=1000"
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Redis e richiesto ma non disponibile*");
    }

    [Fact]
    public void AddAuthLibrary_WithMissingPepper_Throws()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["SecuritySettings:Pepper"] = ""
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*SecuritySettings:Pepper*");
    }

    [Fact]
    public void AddAuthLibrary_WithInvalidFrontendUrl_Throws()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["AuthSettings:FrontendUrl"] = "not-a-valid-url",
            ["RateLimit:RequireRedis"] = "false"
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*AuthSettings:FrontendUrl*");
    }

    [Fact]
    public void AddAuthLibrary_WithShortJwtKey_Throws()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["JwtSettings:Key"] = "short-key",
            ["RateLimit:RequireRedis"] = "false"
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*JwtSettings:Key*");
    }

    [Fact]
    public void AddAuthLibrary_WithPartialRateLimitRules_UsesMergedDefaults()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["RateLimit:Rules:Login:MaxUserAttempts"] = "8",
            ["RateLimit:Rules:Login:MaxIpAttempts"] = "40",
            ["RateLimit:Rules:Login:AttemptWindow"] = "00:10:00",
            ["RateLimit:Rules:Login:LockDuration"] = "00:02:00",
            ["RateLimit:RequireRedis"] = "false"
        });
        var services = new ServiceCollection();

        // Act
        services.AddAuthLibrary<TestUser>(config);
        var provider = services.BuildServiceProvider();

        // Assert
        provider.GetRequiredService<IRateLimitService>().Should().NotBeNull();
    }

    [Fact]
    public void AddAuthLibrary_WithInvalidRateLimitRuleName_Throws()
    {
        // Arrange
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["RateLimit:Rules:UnknownType:MaxUserAttempts"] = "2",
            ["RateLimit:Rules:UnknownType:MaxIpAttempts"] = "5",
            ["RateLimit:Rules:UnknownType:AttemptWindow"] = "00:01:00",
            ["RateLimit:Rules:UnknownType:LockDuration"] = "00:01:00",
            ["RateLimit:RequireRedis"] = "false"
        });
        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*RateLimit:Rules contiene tipo non supportato*");
    }

    private static IConfiguration BuildConfig(IDictionary<string, string?> overrides)
    {
        var settings = new Dictionary<string, string?>
        {
            ["JwtSettings:Key"] = "this-is-a-test-secret-key-with-at-least-32-chars",
            ["JwtSettings:Issuer"] = "TestIssuer",
            ["JwtSettings:Audience"] = "TestAudience",
            ["JwtSettings:AccessTokenLifetimeMinutes"] = "15",
            ["SecuritySettings:Pepper"] = "test-pepper",
            ["MailService:AppMail"] = "noreply@test.com",
            ["MailService:Host"] = "smtp.test.com",
            ["MailService:Port"] = "587",
            ["MailService:SenderName"] = "Test App",
            ["AuthSettings:FrontendUrl"] = "https://test.com",
            ["TemplateSettings:BasePath"] = "templates",
            ["RefreshTokenSettings:RefreshTokenLifetimeDays"] = "30",
            ["RateLimit:RequireRedis"] = "false"
        };

        foreach (var (key, value) in overrides)
        {
            settings[key] = value;
        }

        return new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();
    }
}
