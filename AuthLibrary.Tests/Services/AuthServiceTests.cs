using AuthLibrary.Tests.Helpers;

using MockFactory = AuthLibrary.Tests.Helpers.MockFactory;

namespace AuthLibrary.Tests.Services;

public class AuthServiceBasicTests
{
    private readonly Mock<IAuthRepository<TestUser>> _repositoryMock;
    private readonly Mock<ITokenService<TestUser>> _tokenServiceMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly Mock<IMailService> _mailServiceMock;
    private readonly Mock<IMailTemplateService> _templateServiceMock;
    private readonly Mock<ILogger<AuthService<TestUser>>> _loggerMock;
    private readonly Mock<IPasswordValidator> _passwordValidatorMock;
    private readonly IOptions<SecuritySettings> _securitySettings;
    private readonly IOptions<AuthSettings> _authSettings;
    private readonly IOptions<MailSettings> _mailSettings;
    private readonly AuthService<TestUser> _authService;

    public AuthServiceBasicTests()
    {
        _repositoryMock = MockFactory.CreateAuthRepository<TestUser>();
        _tokenServiceMock = MockFactory.CreateTokenService<TestUser>();
        _rateLimitServiceMock = MockFactory.CreateRateLimitService();
        _mailServiceMock = MockFactory.CreateMailService();
        _templateServiceMock = new Mock<IMailTemplateService>();
        _loggerMock = MockFactory.CreateLogger<AuthService<TestUser>>();
        _passwordValidatorMock = MockFactory.CreatePasswordValidator();

        _securitySettings = MockFactory.CreateOptions(MockFactory.CreateSecuritySettings());
        _authSettings = MockFactory.CreateOptions(new AuthSettings { FrontendUrl = "https://test.com" });
        _mailSettings = MockFactory.CreateOptions(MockFactory.CreateMailSettings());

        _authService = new AuthService<TestUser>(
            _repositoryMock.Object,
            _securitySettings,
            _mailServiceMock.Object,
            _tokenServiceMock.Object,
            _rateLimitServiceMock.Object,
            _templateServiceMock.Object,
            _authSettings,
            _mailSettings,
            _loggerMock.Object,
            _passwordValidatorMock.Object
        );
    }

    #region Login Tests

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsSuccessWithTokens()
    {
        // Arrange
        var username = "testuser";
        var password = "ValidPassword123!";
        var salt = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        
        // Generate proper Argon2 hash to match the service hashing
        var saltBytes = Convert.FromBase64String(salt);
        var pepper = _securitySettings.Value.Pepper;
        var passwordHash = GenerateArgon2Hash(password, saltBytes, pepper);

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithEmail("test@example.com")
            .WithPassword(passwordHash) 
            .WithSalt(salt)
            .AsVerified()
            .Build();

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);
        
        var expectedAccessToken = new AccessTokenResult { Token = "jwt-token", ExpiresInSeconds = 900 };
        var expectedRefreshToken = new RefreshTokenIssueResult
        {
            PlainToken = "refresh-token",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            UserId = user.Id
        };

        _tokenServiceMock.Setup(x => x.GenerateAccessToken(user))
            .Returns(expectedAccessToken);
        _tokenServiceMock.Setup(x => x.CreateRefreshToken(user))
            .ReturnsAsync(expectedRefreshToken);
        _rateLimitServiceMock.Setup(x => x.Reset(RateLimitRequestType.Login, username))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().NotBeNull();
        result.Value.AccessToken.Token.Should().Be("jwt-token");
        result.Value.NewRefreshToken.Should().Be("refresh-token");

        _rateLimitServiceMock.Verify(x => x.Reset(RateLimitRequestType.Login, username), Times.Once);
    }

    [Fact]
    public async Task Login_WithInvalidPassword_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword123!";
        var salt = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var saltBytes = Convert.FromBase64String(salt);
        var pepper = _securitySettings.Value.Pepper;
        var passwordHash = GenerateArgon2Hash(correctPassword, saltBytes, pepper);

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithPassword(passwordHash)
            .WithSalt(salt)
            .AsVerified()
            .Build();


        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.Login(username, wrongPassword);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WithNonExistentUser_ReturnsFailure()
    {
        // Arrange
        var username = "nonexistent";
        var password = "Password123!";

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync((TestUser?)null);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WithUnverifiedEmail_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var password = "Password123!";

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithEmailVerified(false) // Not verified
            .Build();

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WhenRateLimited_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var password = "Password123!";

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(true); // Rate limit reached

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("bloccato");
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Generates Argon2 hash matching the AuthService implementation
    /// </summary>
    private static string GenerateArgon2Hash(string password, byte[] salt, string pepper)
    {
        var config = new Isopoh.Cryptography.Argon2.Argon2Config
        {
            Type = Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
            Version = Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
            TimeCost = 4,
            MemoryCost = 65536,
            Lanes = 4,
            Threads = 4,
            Password = System.Text.Encoding.UTF8.GetBytes(password + pepper),
            Salt = salt,
            HashLength = 32
        };

        using var argon2 = new Isopoh.Cryptography.Argon2.Argon2(config);
        using var hash = argon2.Hash();
        return Convert.ToBase64String(hash.Buffer);
    }

    #endregion
}
