namespace AuthLibrary.Configuration;

public class RateLimitSettings
{
    public Dictionary<string, RateLimitConfiguration> Rules { get; set; } = new();
}
