namespace AuthLibrary.Configuration;

public class RateLimitSettings
{
    public Dictionary<string, RateLimitConfiguration> Rules { get; set; } = new();
    public List<string> TrustedProxyIps { get; set; } = new();
    public bool RequireRedis { get; set; } = true;
}
