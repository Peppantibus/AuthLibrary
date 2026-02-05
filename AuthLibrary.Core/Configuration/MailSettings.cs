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

    /// <summary>
    /// SMTP operation timeout in seconds (connect/auth/send). Default: 30.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Number of retry attempts on transient SMTP errors. Default: 1 (one retry).
    /// </summary>
    public int RetryCount { get; set; } = 1;

    /// <summary>
    /// Delay between retries in milliseconds. Default: 500.
    /// </summary>
    public int RetryDelayMilliseconds { get; set; } = 500;
}
