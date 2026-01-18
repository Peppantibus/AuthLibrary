using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using Microsoft.Extensions.Options;
using System.IO;

namespace AuthLibrary.Services;

public class MailTemplateService : IMailTemplateService
{
    private readonly string _basePath;

    public MailTemplateService(IOptions<TemplateSettings> settings)
    {
        _basePath = settings.Value.BasePath;
    }

    public async Task<string> RenderTemplateAsync(string templateName, Dictionary<string, string> parameters)
    {
        var path = Path.Combine(_basePath, templateName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Template not found: {path}");
        }
        
        var template = await File.ReadAllTextAsync(path);

        foreach (var param in parameters)
        {
            // HTML encode to prevent injection
            var encodedValue = System.Net.WebUtility.HtmlEncode(param.Value);
            template = template.Replace($"{{{{{param.Key}}}}}", encodedValue);
        }

        return template;
    }
}
