namespace Chat.AuthLibrary.Configuration;

public class RateLimitConfiguration
{
    public int MaxUserAttempts { get; set; }
    public int MaxIpAttempts { get; set; }
    public TimeSpan AttemptWindow { get; set; }
    public TimeSpan LockDuration { get; set; }
}
