namespace AuthLibrary.Models.Dto;

public class MailDto
{
    public string From { get; set; } = string.Empty;
    public string EmailTo { get; set; } = string.Empty;
    public List<string>? EmailCC { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public bool IsHtml { get; set; }
}
