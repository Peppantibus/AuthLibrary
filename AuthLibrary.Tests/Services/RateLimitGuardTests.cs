using AuthLibrary.Services;

namespace AuthLibrary.Tests.Services;

public class RateLimitGuardTests
{
    [Fact]
    public async Task EnsureNotBlockedAndRegisterAttempt_WhenBlocked_ReturnsFailure()
    {
        // Arrange
        var rateLimitMock = new Mock<IRateLimitService>();
        rateLimitMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, "user")).ReturnsAsync(true);
        var guard = new RateLimitGuard(rateLimitMock.Object);

        // Act
        var result = await guard.EnsureNotBlockedAndRegisterAttempt(
            RateLimitRequestType.Login,
            "user",
            "blocked",
            "attempt");

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Should().Be("blocked");
        rateLimitMock.Verify(x => x.RegisterAttempted(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task EnsureNotBlockedOrInCooldownAndRegisterAttempt_WhenAllowed_ReturnsSuccess()
    {
        // Arrange
        var rateLimitMock = new Mock<IRateLimitService>();
        rateLimitMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, "user")).ReturnsAsync(false);
        rateLimitMock.Setup(x => x.IsInCooldown(RateLimitRequestType.Login, "user")).ReturnsAsync(false);
        rateLimitMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, "user")).ReturnsAsync(false);
        var guard = new RateLimitGuard(rateLimitMock.Object);

        // Act
        var result = await guard.EnsureNotBlockedOrInCooldownAndRegisterAttempt(
            RateLimitRequestType.Login,
            "user",
            "blocked",
            "cooldown",
            "attempt");

        // Assert
        result.IsSuccess.Should().BeTrue();
        rateLimitMock.Verify(x => x.IsBlocked(RateLimitRequestType.Login, "user"), Times.Once);
        rateLimitMock.Verify(x => x.IsInCooldown(RateLimitRequestType.Login, "user"), Times.Once);
        rateLimitMock.Verify(x => x.RegisterAttempted(RateLimitRequestType.Login, "user"), Times.Once);
    }

    [Fact]
    public async Task EnsureNotBlockedOrInCooldown_WhenInCooldown_ReturnsFailure()
    {
        // Arrange
        var rateLimitMock = new Mock<IRateLimitService>();
        rateLimitMock.Setup(x => x.IsBlocked(RateLimitRequestType.ResetPassword, "mail")).ReturnsAsync(false);
        rateLimitMock.Setup(x => x.IsInCooldown(RateLimitRequestType.ResetPassword, "mail")).ReturnsAsync(true);
        var guard = new RateLimitGuard(rateLimitMock.Object);

        // Act
        var result = await guard.EnsureNotBlockedOrInCooldown(
            RateLimitRequestType.ResetPassword,
            "mail",
            "blocked",
            "cooldown");

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Should().Be("cooldown");
    }
}
