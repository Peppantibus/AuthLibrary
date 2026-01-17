using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthLibrary.Tests.Helpers;

using MockFactory = AuthLibrary.Tests.Helpers.MockFactory;

namespace AuthLibrary.Tests.Services;

public class TokenServiceTests
{
    private readonly Mock<IAuthRepository<TestUser>> _repositoryMock;
    private readonly Mock<ILogger<TokenService<TestUser>>> _loggerMock;
    private readonly IOptions<JwtSettings> _jwtSettings;
    private readonly IOptions<RefreshTokenSettings> _refreshTokenSettings;
    private readonly TokenService<TestUser> _tokenService;

    public TokenServiceTests()
    {
        _repositoryMock = MockFactory.CreateAuthRepository<TestUser>();
        _loggerMock = MockFactory.CreateLogger<TokenService<TestUser>>();
        
        var jwtConfig = MockFactory.CreateJwtSettings();
        _jwtSettings = MockFactory.CreateOptions(jwtConfig);
        _refreshTokenSettings = MockFactory.CreateOptions(MockFactory.CreateRefreshTokenSettings());

        _tokenService = new TokenService<TestUser>(_jwtSettings, _loggerMock.Object, _repositoryMock.Object, _refreshTokenSettings);
    }

    [Fact]
    public void Constructor_WithValidConfiguration_InitializesSuccessfully()
    {
        // Arrange & Act & Assert - If constructor doesn't throw, validation passed
        var service = new TokenService<TestUser>(_jwtSettings, _loggerMock.Object, _repositoryMock.Object, _refreshTokenSettings);
        service.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_WithShortKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var invalidSettings = new JwtSettings
        {
            Key = "short", // Less than 32 bytes
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenLifetimeMinutes = 15
        };
        var options = MockFactory.CreateOptions(invalidSettings);

        // Act & Assert
        var act = () => new TokenService<TestUser>(options, _loggerMock.Object, _repositoryMock.Object, _refreshTokenSettings);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*must be at least 32 bytes*");
    }

    [Fact]
    public void Constructor_WithEmptyKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var invalidSettings = new JwtSettings
        {
            Key = string.Empty,
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenLifetimeMinutes = 15
        };
        var options = MockFactory.CreateOptions(invalidSettings);

        // Act & Assert
        var act = () => new TokenService<TestUser>(options, _loggerMock.Object, _repositoryMock.Object, _refreshTokenSettings);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*JWT Key is not configured*");
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsBase64String()
    {
        // Act
        var token = _tokenService.GenerateRefreshToken();

        // Assert
        token.Should().NotBeNullOrEmpty();
        token.Length.Should().BeGreaterThan(50); // 64 bytes base64 encoded
        
        // Verify it's valid base64
        var act = () => Convert.FromBase64String(token);
        act.Should().NotThrow();
    }

    [Fact]
    public void GenerateRefreshToken_GeneratesUniqueTokens()
    {
        // Act
        var token1 = _tokenService.GenerateRefreshToken();
        var token2 = _tokenService.GenerateRefreshToken();

        // Assert
        token1.Should().NotBe(token2);
    }

    [Fact]
    public void GenerateAccessToken_WithValidUser_ReturnsValidJwtToken()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithId("user-123")
            .WithUsername("testuser")
            .WithEmail("test@example.com")
            .Build();

        // Act
        var result = _tokenService.GenerateAccessToken(user);

        // Assert
        result.Should().NotBeNull();
        result.Token.Should().NotBeNullOrEmpty();
        result.ExpiresInSeconds.Should().Be(_jwtSettings.Value.AccessTokenLifetimeMinutes * 60);

        // Verify the JWT structure
        var handler = new JwtSecurityTokenHandler();
        var canRead = handler.CanReadToken(result.Token);
        canRead.Should().BeTrue();

        var jwt = handler.ReadJwtToken(result.Token);
        jwt.Should().NotBeNull();
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectClaims()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithId("user-456")
            .WithUsername("johndoe")
            .WithEmail("john@example.com")
            .Build();

        // Act
        var result = _tokenService.GenerateAccessToken(user);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.Token);

        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == "user-456");
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.UniqueName && c.Value == "johndoe");
        jwt.Claims.Should().Contain(c => c.Type == "email" && c.Value == "john@example.com");
        jwt.Claims.Should().Contain(c => c.Type == "type" && c.Value == "access");
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti);
    }

    [Fact]
    public void GenerateAccessToken_HasCorrectIssuerAndAudience()
    {
        // Arrange
        var user = TestDataBuilder.User().Build();

        // Act
        var result = _tokenService.GenerateAccessToken(user);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.Token);

        jwt.Issuer.Should().Be(_jwtSettings.Value.Issuer);
        jwt.Audiences.Should().Contain(_jwtSettings.Value.Audience);
    }

    [Fact]
    public async Task CreateRefreshToken_SavesHashedTokenAndReturnsPlainToken()
    {
        // Arrange
        var user = TestDataBuilder.User().WithId("user-789").Build();
        
        _repositoryMock.Setup(x => x.AddRefreshTokenAsync(It.IsAny<RefreshToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _tokenService.CreateRefreshToken(user);

        // Assert
        result.Should().NotBeNull();
        result.PlainToken.Should().NotBeNullOrEmpty();
        result.UserId.Should().Be("user-789");
        result.ExpiresAt.Should().BeCloseTo(DateTime.UtcNow.AddDays(_refreshTokenSettings.Value.RefreshTokenLifetimeDays), TimeSpan.FromSeconds(5));

        // Verify hashed token was stored (not the plain token)
        _repositoryMock.Verify(x => x.AddRefreshTokenAsync(It.Is<RefreshToken>(rt => 
            rt.UserId == "user-789" &&
            rt.TokenHash != result.PlainToken && // Stored hash should be different from plain token
            rt.TokenHash.Length > 0
        )), Times.Once);

        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_ReturnsNewTokensAndUserInfo()
    {
        // Arrange
        var userId = "user-123";
        var plainToken = "plain-refresh-token";
        var hashedToken = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainToken))
        );

        var user = TestDataBuilder.User()
            .WithId(userId)
            .WithUsername("testuser")
            .WithName("Test", "User")
            .Build();

        var existingToken = new RefreshToken
        {
            UserId = userId,
            TokenHash = hashedToken,
            CreatedAt = DateTime.UtcNow.AddDays(-1),
            ExpiresAt = DateTime.UtcNow.AddDays(29),
            RevokedAt = null,
            ReplacedByToken = null
        };

        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(existingToken);
        _repositoryMock.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _repositoryMock.Setup(x => x.UpdateRefreshTokenAsync(It.IsAny<RefreshToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.AddRefreshTokenAsync(It.IsAny<RefreshToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _tokenService.RefreshToken(plainToken);

        // Assert
        result.Should().NotBeNull();
        result.NewRefreshToken.Should().NotBeNullOrEmpty();
        result.NewRefreshToken.Should().NotBe(plainToken); // Should be rotated
        result.AccessToken.Should().NotBeNull();
        result.AccessToken.Token.Should().NotBeNullOrEmpty();
        result.User.Id.Should().Be(userId);
        result.User.Username.Should().Be("testuser");
    }

    [Fact]
    public async Task RefreshToken_WithExpiredToken_ThrowsInvalidOperationException()
    {
        // Arrange
        var plainToken = "expired-token";
        var hashedToken = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainToken))
        );

        var expiredToken = new RefreshToken
        {
            UserId = "user-123",
            TokenHash = hashedToken,
            CreatedAt = DateTime.UtcNow.AddDays(-31),
            ExpiresAt = DateTime.UtcNow.AddDays(-1), // Expired
            RevokedAt = null,
            ReplacedByToken = null
        };

        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(expiredToken);

        // Act & Assert
        var act = async () => await _tokenService.RefreshToken(plainToken);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*non valido*");
    }

    [Fact]
    public async Task RefreshToken_WithRevokedToken_ThrowsInvalidOperationException()
    {
        // Arrange
        var plainToken = "revoked-token";
        var hashedToken = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainToken))
        );

        var revokedToken = new RefreshToken
        {
            UserId = "user-123",
            TokenHash = hashedToken,
            CreatedAt = DateTime.UtcNow.AddDays(-1),
            ExpiresAt = DateTime.UtcNow.AddDays(29),
            RevokedAt = DateTime.UtcNow, // Revoked
            ReplacedByToken = null
        };

        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(revokedToken);

        // Act & Assert
        var act = async () => await _tokenService.RefreshToken(plainToken);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*non valido*");
    }

    [Fact]
    public async Task RefreshToken_WithNonExistentToken_ThrowsInvalidOperationException()
    {
        // Arrange
        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync((RefreshToken?)null);

        // Act & Assert
        var act = async () => await _tokenService.RefreshToken("non-existent-token");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*non valido*");
    }

    [Fact]
    public async Task RefreshToken_WithReusedToken_InvalidatesSessionAndThrows()
    {
        // Arrange - Simulating token reuse attack
        var plainToken = "reused-token";
        var hashedToken = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainToken))
        );

        var reusedToken = new RefreshToken
        {
            UserId = "user-123",
            TokenHash = hashedToken,
            CreatedAt = DateTime.UtcNow.AddDays(-2),
            ExpiresAt = DateTime.UtcNow.AddDays(28),
            RevokedAt = null,
            ReplacedByToken = "some-new-token-hash" // Already replaced
        };

        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(reusedToken);
        _repositoryMock.Setup(x => x.RemoveRefreshTokensByUserIdAsync("user-123"))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        // Act & Assert
        var act = async () => await _tokenService.RefreshToken(plainToken);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*non valido*");

        // Verify all tokens for user were removed
        _repositoryMock.Verify(x => x.RemoveRefreshTokensByUserIdAsync("user-123"), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
    }

    [Fact]
    public async Task RefreshToken_WithTokenCreatedBeforePasswordChange_ThrowsInvalidOperationException()
    {
        // Arrange
        var userId = "user-123";
        var plainToken = "old-token";
        var hashedToken = Convert.ToBase64String(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainToken))
        );

        var passwordChangeTime = DateTime.UtcNow.AddHours(-1);
        var tokenCreationTime = DateTime.UtcNow.AddHours(-2); // Created before password change

        var user = TestDataBuilder.User()
            .WithId(userId)
            .WithPasswordUpdatedAt(passwordChangeTime)
            .Build();

        var oldToken = new RefreshToken
        {
            UserId = userId,
            TokenHash = hashedToken,
            CreatedAt = tokenCreationTime,
            ExpiresAt = DateTime.UtcNow.AddDays(29),
            RevokedAt = null,
            ReplacedByToken = null
        };

        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(oldToken);
        _repositoryMock.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);

        // Act & Assert
        var act = async () => await _tokenService.RefreshToken(plainToken);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*non valido*");
    }

    [Fact]
    public async Task TryRefreshToken_WithInvalidToken_ReturnsFailure()
    {
        // Arrange
        _repositoryMock.Setup(x => x.GetRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync((RefreshToken?)null);

        // Act
        var result = await _tokenService.TryRefreshToken("invalid-token");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("token non valido");
    }
}
