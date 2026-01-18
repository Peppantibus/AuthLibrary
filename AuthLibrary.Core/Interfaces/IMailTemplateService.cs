namespace AuthLibrary.Interfaces;

public interface IMailTemplateService
{
    Task<string> RenderTemplateAsync(string templateName, Dictionary<string, string> parameters);
}
