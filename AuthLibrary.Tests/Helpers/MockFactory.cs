namespace AuthLibrary.Tests.Helpers;

/// <summary>
/// Factory for creating common mocks used across tests
/// </summary>
public static class MockFactory
{
    public static Mock<ILogger<T>> CreateLogger<T>()
    {
        return new Mock<ILogger<T>>();
    }

    public static IOptions<T> CreateOptions<T>(T value) where T : class
    {
        var mock = new Mock<IOptions<T>>();
        mock.Setup(x => x.Value).Returns(value);
        return mock.Object;
    }

    public static Mock<IAuthRepository<TUser>> CreateAuthRepository<TUser>() where TUser : class, IAuthUser
    {
        return new Mock<IAuthRepository<TUser>>();
    }

    public static Mock<IRedisService> CreateRedisService()
    {
        return new Mock<IRedisService>();
    }

    public static Mock<IMailService> CreateMailService()
    {
        return new Mock<IMailService>();
    }

    public static Mock<ITokenService<TUser>> CreateTokenService<TUser>() where TUser : IAuthUser
    {
        return new Mock<ITokenService<TUser>>();
    }

    public static Mock<IRateLimitService> CreateRateLimitService()
    {
        return new Mock<IRateLimitService>();
    }

    public static Mock<IPasswordValidator> CreatePasswordValidator()
    {
        return new Mock<IPasswordValidator>();
    }

    public static SecuritySettings CreateSecuritySettings()
    {
        return new SecuritySettings
        {
            Pepper = "test-pepper-secret-key-for-testing-purposes-only"
        };
    }

    public static JwtSettings CreateJwtSettings()
    {
        return new JwtSettings
        {
            Key = "this-is-a-test-secret-key-with-at-least-32-chars-for-jwt-signing",
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenLifetimeMinutes = 15
        };
    }

    public static RefreshTokenSettings CreateRefreshTokenSettings()
    {
        return new RefreshTokenSettings
        {
            RefreshTokenLifetimeDays = 30
        };
    }

    public static MailSettings CreateMailSettings()
    {
        return new MailSettings
        {
            AppMail = "noreply@test.com",
            Host = "smtp.test.com",
            Port = 587,
            SenderName = "Test App",
            Username = "testuser",
            Password = "testpassword",
            UseSsl = true
        };
    }

    public static TemplateSettings CreateTemplateSettings()
    {
        return new TemplateSettings
        {
            BasePath = "templates"
        };
    }
}
