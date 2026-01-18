namespace AuthLibrary.Configuration;

public class MailSettings
{
    public string AppMail { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    
    /// <summary>
    /// If true, use SSL/TLS for connection. If false with port 587, STARTTLS will be attempted.
    /// </summary>
    public bool UseSsl { get; set; } = true;
    
    /// <summary>
    /// SMTP authentication username (often the email address).
    /// </summary>
    public string? Username { get; set; }
    
    /// <summary>
    /// SMTP authentication password or app-specific password.
    /// </summary>
    public string? Password { get; set; }
    
    /// <summary>
    /// Display name for sender in emails.
    /// </summary>
    public string SenderName { get; set; } = "AuthLibrary";
}
