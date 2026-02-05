namespace AuthLibrary.Configuration;

public class GoogleAuthSettings
{
    public string ClientId { get; set; } = string.Empty;
    public string? AllowedHostedDomain { get; set; }
}
