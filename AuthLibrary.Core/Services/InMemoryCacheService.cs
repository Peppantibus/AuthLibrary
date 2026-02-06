using AuthLibrary.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace AuthLibrary.Services;

/// <summary>
/// In-memory fallback for Redis when Redis is unavailable or not configured.
/// Uses MemoryCache for rate limiting and session management.
/// </summary>
public class InMemoryCacheService : IRedisService
{
    private readonly IMemoryCache _cache;
    private readonly object[] _lockStripes;
    private readonly TimeSpan _defaultIncrementTtl;

    private sealed class CounterEntry
    {
        public double Value { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

    public InMemoryCacheService(
        IMemoryCache cache,
        TimeSpan? defaultIncrementTtl = null,
        int lockStripeCount = 256)
    {
        _cache = cache;
        _defaultIncrementTtl = defaultIncrementTtl ?? TimeSpan.FromMinutes(15);
        _lockStripes = BuildLockStripes(lockStripeCount);
    }

    public Task<string?> GetValue(string key)
    {
        _cache.TryGetValue(key, out string? value);
        return Task.FromResult(value);
    }

    public Task SetValue(string key, string value, TimeSpan expiration)
    {
        _cache.Set(key, value, expiration);
        return Task.CompletedTask;
    }

    public Task<bool> TrySetValue(string key, string value, TimeSpan expiration)
    {
        var gate = GetLockStripe(key);
        lock (gate)
        {
            if (_cache.TryGetValue(key, out _))
            {
                return Task.FromResult(false);
            }

            _cache.Set(key, value, expiration);
            return Task.FromResult(true);
        }
    }

    public Task<double> Increment(string key, double value)
    {
        var gate = GetLockStripe(key);
        lock (gate)
        {
            var now = DateTime.UtcNow;

            if (_cache.TryGetValue(key, out object? existing))
            {
                if (existing is CounterEntry counter && counter.ExpiresAt > now)
                {
                    counter.Value += value;
                    _cache.Set(key, counter, counter.ExpiresAt);
                    return Task.FromResult(counter.Value);
                }

                if (existing is double current)
                {
                    var newValue = current + value;
                    var expiresAt = now.Add(_defaultIncrementTtl);
                    _cache.Set(key, new CounterEntry { Value = newValue, ExpiresAt = expiresAt }, expiresAt);
                    return Task.FromResult(newValue);
                }
            }

            var initialValue = value;
            var initialExpiresAt = now.Add(_defaultIncrementTtl);
            _cache.Set(key, new CounterEntry { Value = initialValue, ExpiresAt = initialExpiresAt }, initialExpiresAt);
            return Task.FromResult(initialValue);
        }
    }

    public Task Remove(string key)
    {
        _cache.Remove(key);
        return Task.CompletedTask;
    }

    public Task<bool> Expire(string key, TimeSpan expiration)
    {
        // Re-set with new expiration if exists
        if (_cache.TryGetValue(key, out object? value))
        {
            if (value is CounterEntry counter)
            {
                counter.ExpiresAt = DateTime.UtcNow.Add(expiration);
                _cache.Set(key, counter, counter.ExpiresAt);
            }
            else
            {
                _cache.Set(key, value, expiration);
            }
            return Task.FromResult(true);
        }
        return Task.FromResult(false);
    }

    private object GetLockStripe(string key)
    {
        var hash = key.GetHashCode();
        var index = (hash & 0x7fffffff) % _lockStripes.Length;
        return _lockStripes[index];
    }

    private static object[] BuildLockStripes(int lockStripeCount)
    {
        var size = lockStripeCount <= 0 ? 256 : lockStripeCount;
        var stripes = new object[size];
        for (var i = 0; i < size; i++)
        {
            stripes[i] = new object();
        }

        return stripes;
    }
}
