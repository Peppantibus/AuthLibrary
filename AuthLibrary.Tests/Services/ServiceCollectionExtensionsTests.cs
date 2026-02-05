using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AuthLibrary.Tests.Helpers;
using AuthLibrary.Extensions;

namespace AuthLibrary.Tests.Services;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthLibrary_WithNoRedisUrl_RegistersInMemoryCacheService()
    {
        // Arrange
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
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
                ["RateLimit:RequireRedis"] = "false"
            })
            .Build();

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
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
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
                ["RateLimit:RequireRedis"] = "true"
            })
            .Build();

        var services = new ServiceCollection();

        // Act
        var act = () => services.AddAuthLibrary<TestUser>(config);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*RequireRedis*");
    }
}
