using Chat.AuthLibrary.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using System.Collections.Concurrent;

namespace Chat.AuthLibrary.Services;

/// <summary>
/// In-memory fallback for Redis when Redis is unavailable or not configured.
/// Uses MemoryCache for rate limiting and session management.
/// </summary>
public class InMemoryCacheService : IRedisService
{
    private readonly IMemoryCache _cache;
    private readonly ConcurrentDictionary<string, object> _locks = new();
    private readonly TimeSpan _defaultIncrementTtl;

    private sealed class CounterEntry
    {
        public double Value { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

    public InMemoryCacheService(IMemoryCache cache, TimeSpan? defaultIncrementTtl = null)
    {
        _cache = cache;
        _defaultIncrementTtl = defaultIncrementTtl ?? TimeSpan.FromMinutes(15);
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

    public Task<double> Increment(string key, double value)
    {
        var gate = _locks.GetOrAdd(key, _ => new object());
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
        _locks.TryRemove(key, out _);
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
}
