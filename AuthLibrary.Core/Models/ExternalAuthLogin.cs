namespace AuthLibrary.Models;

public class ExternalAuthLogin
{
    public string Provider { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
