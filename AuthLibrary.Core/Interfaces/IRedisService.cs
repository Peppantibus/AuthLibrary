namespace Chat.AuthLibrary.Interfaces;

public interface IRedisService
{
    Task SetValue(string key, string value, TimeSpan ttl);
    Task<string?> GetValue(string key);
    Task Remove(string key);
    Task<double> Increment(string key, double value);
    Task<bool> Expire(string key, TimeSpan ttl);
}
