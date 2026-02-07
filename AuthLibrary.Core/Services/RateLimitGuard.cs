using AuthLibrary.Enum;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;

namespace AuthLibrary.Services;

public sealed class RateLimitGuard
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

    public async Task<Result> EnsureNotBlockedAndRegisterAttempt(
        RateLimitRequestType type,
        string identifier,
        string blockedErrorMessage,
        string attemptErrorMessage)
    {
        var blocked = await EnsureNotBlocked(type, identifier, blockedErrorMessage);
        if (blocked.IsFailure)
        {
            return blocked;
        }

        return await RegisterAttempt(type, identifier, attemptErrorMessage);
    }

    public async Task<Result> EnsureNotBlockedOrInCooldown(
        RateLimitRequestType type,
        string identifier,
        string blockedErrorMessage,
        string cooldownErrorMessage)
    {
        var blocked = await EnsureNotBlocked(type, identifier, blockedErrorMessage);
        if (blocked.IsFailure)
        {
            return blocked;
        }

        return await EnsureNotInCooldown(type, identifier, cooldownErrorMessage);
    }

    public async Task<Result> EnsureNotBlockedOrInCooldownAndRegisterAttempt(
        RateLimitRequestType type,
        string identifier,
        string blockedErrorMessage,
        string cooldownErrorMessage,
        string attemptErrorMessage)
    {
        var gated = await EnsureNotBlockedOrInCooldown(type, identifier, blockedErrorMessage, cooldownErrorMessage);
        if (gated.IsFailure)
        {
            return gated;
        }

        return await RegisterAttempt(type, identifier, attemptErrorMessage);
    }
}
