using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;

namespace AuthLibrary.Services;

internal sealed class RateLimitGuard
{
    private readonly IRateLimitService _rateLimitService;

    public RateLimitGuard(IRateLimitService rateLimitService)
    {
        _rateLimitService = rateLimitService;
    }

    public async Task<Result> EnsureNotBlocked(RateLimitRequestType type, string identifier, string errorMessage)
    {
        if (await _rateLimitService.IsBlocked(type, identifier))
        {
            return Result.Fail(errorMessage);
        }

        return Result.Ok();
    }

    public async Task<Result> EnsureNotInCooldown(RateLimitRequestType type, string identifier, string errorMessage)
    {
        if (await _rateLimitService.IsInCooldown(type, identifier))
        {
            return Result.Fail(errorMessage);
        }

        return Result.Ok();
    }

    public async Task<Result> RegisterAttempt(RateLimitRequestType type, string identifier, string errorMessage)
    {
        if (await _rateLimitService.RegisterAttempted(type, identifier))
        {
            return Result.Fail(errorMessage);
        }

        return Result.Ok();
    }
}
