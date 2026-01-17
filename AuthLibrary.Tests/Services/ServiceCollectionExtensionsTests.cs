using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AuthLibrary.Tests.Helpers;
using Chat.AuthLibrary.Extensions;

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
                ["TemplateSettings:BasePath"] = "templates"
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
}
