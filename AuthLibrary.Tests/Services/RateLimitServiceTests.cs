using System.Security.Cryptography;
using AuthLibrary.Tests.Helpers;
using Microsoft.AspNetCore.Http;

using MockFactory = AuthLibrary.Tests.Helpers.MockFactory;

namespace AuthLibrary.Tests.Services;

public class RateLimitServiceTests
{
    private readonly Mock<IRedisService> _redisServiceMock;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private readonly RateLimitService _rateLimitService;
    private readonly HttpContext _httpContext;

    public RateLimitServiceTests()
    {
        _redisServiceMock = MockFactory.CreateRedisService();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        
        // Setup HttpContext with a mock IP
        _httpContext = new DefaultHttpContext();
        _httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns(_httpContext);

        _rateLimitService = new RateLimitService(
            _redisServiceMock.Object,
            _httpContextAccessorMock.Object,
            trustedProxyIps: new[] { "192.168.1.100" });
    }

    [Fact]
    public async Task IsBlocked_WhenNoBlockExists_ReturnsFalse()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock.Setup(x => x.GetValue(It.IsAny<string>())).ReturnsAsync((string?)null);

        // Act
        var result = await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task IsBlocked_WhenIpIsBlocked_ReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:192.168.1.100"))
            .ReturnsAsync("1");
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:{identifier}"))
            .ReturnsAsync((string?)null);

        // Act
        var result = await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsBlocked_WhenUserIsBlocked_ReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:192.168.1.100"))
            .ReturnsAsync((string?)null);
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:{identifier}"))
            .ReturnsAsync("1");

        // Act
        var result = await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task RegisterAttempted_FirstAttempt_ReturnsfalseAndSetsExpiration()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock.Setup(x => x.Increment(It.IsAny<string>(), It.IsAny<double>())).ReturnsAsync(1);

        // Act
        var result = await _rateLimitService.RegisterAttempted(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeFalse();
        _redisServiceMock.Verify(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100", 1), Times.Once);
        _redisServiceMock.Verify(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:{identifier}", 1), Times.Once);
        _redisServiceMock.Verify(x => x.Expire(It.IsAny<string>(), It.IsAny<TimeSpan>()), Times.Exactly(2));
    }

    [Fact]
    public async Task RegisterAttempted_ExceedsIpLimit_BlocksIpAndReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        var ipAttempts = 21; // Exceeds default MaxIpAttempts of 20 for Login
        
        _redisServiceMock
            .Setup(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100", 1))
            .ReturnsAsync(ipAttempts);
        _redisServiceMock
            .Setup(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:{identifier}", 1))
            .ReturnsAsync(1);

        // Act
        var result = await _rateLimitService.RegisterAttempted(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeTrue();
        _redisServiceMock.Verify(
            x => x.SetValue($"rl:lock:{RateLimitRequestType.Login}:ip:192.168.1.100", "1", It.IsAny<TimeSpan>()), 
            Times.Once);
    }

    [Fact]
    public async Task RegisterAttempted_ExceedsUserLimit_BlocksUserAndReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        var userAttempts = 6; // Exceeds default MaxUserAttempts of 5 for Login
        
        _redisServiceMock
            .Setup(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100", 1))
            .ReturnsAsync(1);
        _redisServiceMock
            .Setup(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:{identifier}", 1))
            .ReturnsAsync(userAttempts);

        // Act
        var result = await _rateLimitService.RegisterAttempted(RateLimitRequestType.Login, identifier);

        // Assert
        result.Should().BeTrue();
        _redisServiceMock.Verify(
            x => x.SetValue($"rl:lock:{RateLimitRequestType.Login}:{identifier}", "1", It.IsAny<TimeSpan>()), 
            Times.Once);
    }

    [Fact]
    public async Task Reset_RemovesAttemptsForBothIpAndUser()
    {
        // Arrange
        var identifier = "user@test.com";

        // Act
        await _rateLimitService.Reset(RateLimitRequestType.Login, identifier);

        // Assert
        _redisServiceMock.Verify(x => x.Remove($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100"), Times.Once);
        _redisServiceMock.Verify(x => x.Remove($"rl:attempt:{RateLimitRequestType.Login}:{identifier}"), Times.Once);
    }

    [Fact]
    public async Task IsInCooldown_WhenCooldownExists_ReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:cooldown:{RateLimitRequestType.VerifyEmail}:{identifier}"))
            .ReturnsAsync("1");

        // Act
        var result = await _rateLimitService.IsInCooldown(RateLimitRequestType.VerifyEmail, identifier);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsInCooldown_WhenNoCooldownExists_ReturnsFalse()
    {
        // Arrange
        var identifier = "user@test.com";
        _redisServiceMock
            .Setup(x => x.GetValue($"rl:cooldown:{RateLimitRequestType.VerifyEmail}:{identifier}"))
            .ReturnsAsync((string?)null);

        // Act
        var result = await _rateLimitService.IsInCooldown(RateLimitRequestType.VerifyEmail, identifier);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task StartCooldown_SetsCooldownWithDuration()
    {
        // Arrange
        var identifier = "user@test.com";
        var duration = TimeSpan.FromMinutes(5);

        // Act
        await _rateLimitService.StartCooldown(RateLimitRequestType.VerifyEmail, identifier, duration);

        // Assert
        _redisServiceMock.Verify(
            x => x.SetValue($"rl:cooldown:{RateLimitRequestType.VerifyEmail}:{identifier}", "1", duration), 
            Times.Once);
    }

    [Fact]
    public async Task GetClientIP_WithXForwardedForHeader_UsesFirstIP()
    {
        // Arrange
        var identifier = "user@test.com";
        _httpContext.Request.Headers["X-Forwarded-For"] = "203.0.113.1, 198.51.100.1";
        _redisServiceMock.Setup(x => x.GetValue(It.IsAny<string>())).ReturnsAsync((string?)null);

        // Act
        await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert - Should use the X-Forwarded-For IP (203.0.113.1)
        _redisServiceMock.Verify(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:203.0.113.1"), Times.Once);
    }

    [Theory]
    [InlineData(RateLimitRequestType.Login, 5, 20)]
    [InlineData(RateLimitRequestType.Register, 3, 10)]
    [InlineData(RateLimitRequestType.VerifyEmail, 5, 15)]
    [InlineData(RateLimitRequestType.ResetPassword, 3, 10)]
    public async Task RegisterAttempted_DifferentRequestTypes_UsesCorrectLimits(
        RateLimitRequestType type, 
        int maxUserAttempts, 
        int maxIpAttempts)
    {
        // Arrange
        var identifier = "user@test.com";
        var ipKey = $"rl:attempt:{type}:ip:192.168.1.100";
        var userKey = $"rl:attempt:{type}:{identifier}";

        // Test just below the limit - should not block
        _redisServiceMock
            .Setup(x => x.Increment(ipKey, 1))
            .ReturnsAsync(maxIpAttempts); // At the limit, not over
        _redisServiceMock
            .Setup(x => x.Increment(userKey, 1))
            .ReturnsAsync(maxUserAttempts); // At the limit, not over

        // Act
        var result = await _rateLimitService.RegisterAttempted(type, identifier);

        // Assert
        result.Should().BeFalse();
    }
}
