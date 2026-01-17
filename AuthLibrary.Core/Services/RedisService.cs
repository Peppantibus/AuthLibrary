using Chat.AuthLibrary.Interfaces;
using StackExchange.Redis;

namespace Chat.AuthLibrary.Services;

public class RedisService : IRedisService
{
    private readonly IDatabase _redisDb;

    public RedisService(IConnectionMultiplexer mux)
    {
        _redisDb = mux.GetDatabase();
    }

    public async Task SetValue(string key, string value, TimeSpan ttl)
    {
        await _redisDb.StringSetAsync(key, value, ttl);
    }

    public async Task<string?> GetValue(string key)
    {
        return await _redisDb.StringGetAsync(key);
    }

    public async Task Remove(string key) 
    {
        await _redisDb.KeyDeleteAsync(key);
    }

    public async Task<double> Increment(string key, double value)
    {
        return await _redisDb.StringIncrementAsync(key, value);
    }

    public async Task<bool> Expire(string key, TimeSpan ttl)
    {
        return await _redisDb.KeyExpireAsync(key, ttl);   
    }
}
