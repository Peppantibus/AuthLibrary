using AuthLibrary.Enum;

namespace AuthLibrary.Interfaces;

public interface IRateLimitService
{
    Task<bool> IsBlocked(RateLimitRequestType type, string identifier);
    Task<bool> RegisterAttempted(RateLimitRequestType type, string identifier);
    Task Reset(RateLimitRequestType type, string identifier);
    Task<bool> IsInCooldown(RateLimitRequestType type, string identifier);
    Task StartCooldown(RateLimitRequestType type, string identifier, TimeSpan duration);
    Task<bool> TryStartCooldown(RateLimitRequestType type, string identifier, TimeSpan duration);
    Task ClearCooldown(RateLimitRequestType type, string identifier);
}
