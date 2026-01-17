using Microsoft.Extensions.Caching.Memory;

namespace AuthLibrary.Tests.Services;

public class InMemoryCacheServiceTests
{
    [Fact]
    public async Task SetValue_ThenGetValue_ReturnsStoredValue()
    {
        // Arrange
        var cache = new MemoryCache(new MemoryCacheOptions());
        var service = new InMemoryCacheService(cache);

        // Act
        await service.SetValue("key", "value", TimeSpan.FromMinutes(1));
        var result = await service.GetValue("key");

        // Assert
        result.Should().Be("value");
    }

    [Fact]
    public async Task Increment_MultipleTimes_ReturnsAccumulatedValue()
    {
        // Arrange
        var cache = new MemoryCache(new MemoryCacheOptions());
        var service = new InMemoryCacheService(cache);

        // Act
        var first = await service.Increment("counter", 1);
        var second = await service.Increment("counter", 2);

        // Assert
        first.Should().Be(1);
        second.Should().Be(3);
    }

    [Fact]
    public async Task Remove_DeletesKey()
    {
        // Arrange
        var cache = new MemoryCache(new MemoryCacheOptions());
        var service = new InMemoryCacheService(cache);

        await service.SetValue("key", "value", TimeSpan.FromMinutes(1));

        // Act
        await service.Remove("key");
        var result = await service.GetValue("key");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task Expire_ReturnsFalseForMissingKey_TrueForExistingKey()
    {
        // Arrange
        var cache = new MemoryCache(new MemoryCacheOptions());
        var service = new InMemoryCacheService(cache);

        // Act
        var missingResult = await service.Expire("missing", TimeSpan.FromSeconds(1));
        await service.SetValue("key", "value", TimeSpan.FromMinutes(1));
        var existingResult = await service.Expire("key", TimeSpan.FromSeconds(1));

        // Assert
        missingResult.Should().BeFalse();
        existingResult.Should().BeTrue();
    }
}
