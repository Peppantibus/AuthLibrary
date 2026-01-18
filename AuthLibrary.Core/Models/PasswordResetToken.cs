namespace AuthLibrary.Models;

public class PasswordResetToken
{
    public string UserId { get; set; } = string.Empty;
    public string TokenHash { get; set; } = string.Empty; // SHA256 hash of the token
    public DateTime ExpiresAt { get; set; }
}
