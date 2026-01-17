using Chat.AuthLibrary.Models.Dto;

namespace Chat.AuthLibrary.Interfaces;

public interface IMailService
{
    Task SendAsync(MailDto mail);
}
