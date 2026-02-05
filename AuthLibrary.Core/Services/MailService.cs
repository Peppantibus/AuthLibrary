using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Models.Dto;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using System.IO;

namespace AuthLibrary.Services;

public class MailService : IMailService
{
    private readonly MailSettings _settings;
    private readonly ILogger<MailService> _logger;

    public MailService(IOptions<MailSettings> settings, ILogger<MailService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task SendAsync(MailDto mail)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_settings.SenderName, _settings.AppMail)); 
        message.To.Add(new MailboxAddress("", mail.EmailTo));

        if (mail.EmailCC != null)
        {
            message.Cc.AddRange(
                mail.EmailCC
                    .Where(e => !string.IsNullOrWhiteSpace(e))
                    .Select(e => new MailboxAddress("", e))
            );
        }

        message.Subject = mail.Subject;

        var builder = new BodyBuilder();

        if (mail.IsHtml)
        {
            builder.HtmlBody = mail.Body;
            builder.TextBody = "Il tuo client email non supporta HTML.";
        }
        else
        {
            builder.TextBody = mail.Body;
        }

        message.Body = builder.ToMessageBody();

        using var client = new MailKit.Net.Smtp.SmtpClient
        {
            Timeout = Math.Max(1, _settings.TimeoutSeconds) * 1000
        };

        // Configure SSL/TLS options
        var secureSocketOptions = _settings.UseSsl 
            ? SecureSocketOptions.SslOnConnect 
            : SecureSocketOptions.StartTls;

        var attempts = Math.Max(0, _settings.RetryCount) + 1;
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            try
            {
                await client.ConnectAsync(_settings.Host, _settings.Port, secureSocketOptions);
                
                // Authenticate if credentials are provided
                if (!string.IsNullOrEmpty(_settings.Username) && !string.IsNullOrEmpty(_settings.Password))
                {
                    await client.AuthenticateAsync(_settings.Username, _settings.Password);
                }
                
                await client.SendAsync(message);
                await client.DisconnectAsync(true);
                return;
            }
            catch (Exception ex) when (IsTransient(ex) && attempt < attempts)
            {
                _logger.LogWarning(ex, "Invio email fallito (tentativo {attempt}/{total}), retry...", attempt, attempts);
                try
                {
                    if (client.IsConnected)
                    {
                        await client.DisconnectAsync(true);
                    }
                }
                catch
                {
                    // ignore disconnect errors during retry
                }
                var delayMs = GetBackoffDelayMs(_settings.RetryDelayMilliseconds, attempt);
                await Task.Delay(delayMs);
            }
        }
    }

    private static bool IsTransient(Exception ex)
    {
        return ex is MailKit.Net.Smtp.SmtpCommandException ||
               ex is MailKit.Net.Smtp.SmtpProtocolException ||
               ex is IOException ||
               ex is TimeoutException;
    }

    private static int GetBackoffDelayMs(int baseDelayMs, int attempt)
    {
        var safeBase = Math.Max(0, baseDelayMs);
        var exponent = Math.Max(0, attempt - 1);
        var delay = safeBase * Math.Pow(2, exponent);
        return (int)Math.Min(30000, delay); // cap at 30s to avoid excessive waits
    }
}
