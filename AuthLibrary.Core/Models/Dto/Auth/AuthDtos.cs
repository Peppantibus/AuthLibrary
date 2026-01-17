namespace Chat.AuthLibrary.Models.Dto.Auth;

public class RefreshTokenDto
{
    public string NewRefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiresAt { get; set; }
    public AccessTokenResult AccessToken { get; set; } = new();
    public UserDto User { get; set; } = new();
}

public class RefreshTokenIssueResult
{
    public string PlainToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string UserId { get; set; } = string.Empty;
}

public class AccessTokenResult
{
    public string Token { get; set; } = string.Empty;
    public int ExpiresInSeconds { get; set; }
}

public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}

public class ResetPasswordDto
{
    public string Token { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
