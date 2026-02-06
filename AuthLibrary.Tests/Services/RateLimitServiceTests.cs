using System.Security.Cryptography;
using AuthLibrary.Tests.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;

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
    public async Task RegisterAttempted_WithEmptyIdentifier_TracksOnlyIp()
    {
        // Arrange
        _redisServiceMock.Setup(x => x.Increment(It.IsAny<string>(), It.IsAny<double>())).ReturnsAsync(1);

        // Act
        var result = await _rateLimitService.RegisterAttempted(RateLimitRequestType.Login, string.Empty);

        // Assert
        result.Should().BeFalse();
        _redisServiceMock.Verify(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100", 1), Times.Once);
        _redisServiceMock.Verify(x => x.Increment($"rl:attempt:{RateLimitRequestType.Login}:", 1), Times.Never);
        _redisServiceMock.Verify(x => x.Expire($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100", It.IsAny<TimeSpan>()), Times.Once);
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
    public async Task Reset_RemovesOnlyUserScopedState()
    {
        // Arrange
        var identifier = "user@test.com";

        // Act
        await _rateLimitService.Reset(RateLimitRequestType.Login, identifier);

        // Assert
        _redisServiceMock.Verify(x => x.Remove($"rl:attempt:{RateLimitRequestType.Login}:{identifier}"), Times.Once);
        _redisServiceMock.Verify(x => x.Remove($"rl:lock:{RateLimitRequestType.Login}:{identifier}"), Times.Once);
        _redisServiceMock.Verify(x => x.Remove($"rl:attempt:{RateLimitRequestType.Login}:ip:192.168.1.100"), Times.Never);
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
    public async Task TryStartCooldown_WhenKeyMissing_ReturnsTrue()
    {
        // Arrange
        var identifier = "user@test.com";
        var duration = TimeSpan.FromMinutes(5);
        _redisServiceMock
            .Setup(x => x.TrySetValue($"rl:cooldown:{RateLimitRequestType.VerifyEmail}:{identifier}", "1", duration))
            .ReturnsAsync(true);

        // Act
        var result = await _rateLimitService.TryStartCooldown(RateLimitRequestType.VerifyEmail, identifier, duration);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task TryStartCooldown_WhenKeyExists_ReturnsFalse()
    {
        // Arrange
        var identifier = "user@test.com";
        var duration = TimeSpan.FromMinutes(5);
        _redisServiceMock
            .Setup(x => x.TrySetValue($"rl:cooldown:{RateLimitRequestType.VerifyEmail}:{identifier}", "1", duration))
            .ReturnsAsync(false);

        // Act
        var result = await _rateLimitService.TryStartCooldown(RateLimitRequestType.VerifyEmail, identifier, duration);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task GetClientIP_WithSpoofedXForwardedFor_UsesRightmostNonTrustedIp()
    {
        // Arrange
        var identifier = "user@test.com";
        _httpContext.Request.Headers["X-Forwarded-For"] = "203.0.113.1, 198.51.100.1";
        _redisServiceMock.Setup(x => x.GetValue(It.IsAny<string>())).ReturnsAsync((string?)null);

        // Act
        await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert - Should ignore spoofed leftmost IP and use rightmost appended by proxy
        _redisServiceMock.Verify(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:198.51.100.1"), Times.Once);
    }

    [Fact]
    public async Task GetClientIP_WithInvalidXForwardedFor_FallsBackToRemoteIp()
    {
        // Arrange
        var identifier = "user@test.com";
        _httpContext.Request.Headers["X-Forwarded-For"] = "not-an-ip, also-invalid";
        _redisServiceMock.Setup(x => x.GetValue(It.IsAny<string>())).ReturnsAsync((string?)null);

        // Act
        await _rateLimitService.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert - Invalid forwarded values are ignored
        _redisServiceMock.Verify(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:192.168.1.100"), Times.Once);
    }

    [Fact]
    public async Task GetClientIP_WithUntrustedProxyHeader_UsesRemoteIpFallback()
    {
        // Arrange
        var identifier = "user@test.com";
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.10");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.10";

        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(context);

        var redis = MockFactory.CreateRedisService();
        redis.Setup(x => x.GetValue(It.IsAny<string>())).ReturnsAsync((string?)null);

        var service = new RateLimitService(
            redis.Object,
            accessor.Object,
            trustedProxyIps: Array.Empty<string>());

        // Act
        await service.IsBlocked(RateLimitRequestType.Login, identifier);

        // Assert
        redis.Verify(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:10.0.0.10"), Times.Once);
        redis.Verify(x => x.GetValue($"rl:lock:{RateLimitRequestType.Login}:ip:203.0.113.10"), Times.Never);
    }

    [Theory]
    [InlineData(RateLimitRequestType.Login, 5, 20)]
    [InlineData(RateLimitRequestType.Register, 3, 10)]
    [InlineData(RateLimitRequestType.VerifyEmail, 5, 15)]
    [InlineData(RateLimitRequestType.ResetPassword, 3, 10)]
    [InlineData(RateLimitRequestType.RefreshToken, 30, 60)]
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

    [Fact]
    public void BuildConfig_WithPartialOverrides_MergesWithDefaults()
    {
        // Arrange
        var settings = new RateLimitSettings
        {
            Rules = new Dictionary<string, RateLimitConfiguration>
            {
                ["Login"] = new RateLimitConfiguration
                {
                    MaxUserAttempts = 7,
                    MaxIpAttempts = 30,
                    AttemptWindow = TimeSpan.FromMinutes(10),
                    LockDuration = TimeSpan.FromMinutes(2)
                }
            }
        };

        // Act
        var config = RateLimitService.BuildConfig(settings);

        // Assert
        config[RateLimitRequestType.Login].MaxUserAttempts.Should().Be(7);
        config.Should().ContainKey(RateLimitRequestType.Register);
        config.Should().ContainKey(RateLimitRequestType.VerifyEmail);
        config.Should().ContainKey(RateLimitRequestType.ResetPassword);
        config.Should().ContainKey(RateLimitRequestType.ExternalLogin);
        config.Should().ContainKey(RateLimitRequestType.RefreshToken);
    }

    [Fact]
    public async Task TryStartCooldown_WithConcurrentCalls_AllowsSingleWinner()
    {
        // Arrange
        var cache = new MemoryCache(new MemoryCacheOptions());
        var redis = new InMemoryCacheService(cache);
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(context);

        var service = new RateLimitService(redis, accessor.Object);
        var attempts = Enumerable.Range(0, 20)
            .Select(_ => service.TryStartCooldown(
                RateLimitRequestType.ExternalLogin,
                "same-key",
                TimeSpan.FromMinutes(1)))
            .ToArray();

        // Act
        var results = await Task.WhenAll(attempts);

        // Assert
        results.Count(x => x).Should().Be(1);
        results.Count(x => !x).Should().Be(19);
    }
}
