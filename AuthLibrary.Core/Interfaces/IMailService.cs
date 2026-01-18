using AuthLibrary.Models.Dto;

namespace AuthLibrary.Interfaces;

public interface IMailService
{
    Task SendAsync(MailDto mail);
}
