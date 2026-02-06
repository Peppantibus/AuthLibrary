namespace AuthLibrary.Models.Dto.Auth;

public sealed class ExternalUserInfo
{
    public string Subject { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public bool EmailVerified { get; init; }
    public string? Nonce { get; init; }
    public DateTime ExpiresAtUtc { get; init; }
    public string? Name { get; init; }
    public string? GivenName { get; init; }
    public string? FamilyName { get; init; }
}
