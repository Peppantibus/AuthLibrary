using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Models.Dto;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthLibrary.Services;

public class MailService : IMailService
{
    private readonly MailSettings _settings;

    public MailService(IOptions<MailSettings> settings)
    {
        _settings = settings.Value;
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

        using var client = new MailKit.Net.Smtp.SmtpClient();

        // Configure SSL/TLS options
        var secureSocketOptions = _settings.UseSsl 
            ? SecureSocketOptions.SslOnConnect 
            : SecureSocketOptions.StartTls;

        await client.ConnectAsync(_settings.Host, _settings.Port, secureSocketOptions);
        
        // Authenticate if credentials are provided
        if (!string.IsNullOrEmpty(_settings.Username) && !string.IsNullOrEmpty(_settings.Password))
        {
            await client.AuthenticateAsync(_settings.Username, _settings.Password);
        }
        
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
}
