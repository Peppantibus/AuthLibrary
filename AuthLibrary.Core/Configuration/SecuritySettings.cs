namespace AuthLibrary.Configuration;

public class SecuritySettings
{
    public string Pepper { get; set; } = string.Empty;
    public bool RequireTransactionalRepository { get; set; } = true;
}
