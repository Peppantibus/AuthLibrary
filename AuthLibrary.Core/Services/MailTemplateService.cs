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
        if (string.IsNullOrWhiteSpace(templateName))
        {
            throw new ArgumentException("Template name is required.", nameof(templateName));
        }

        if (Path.IsPathRooted(templateName))
        {
            throw new InvalidOperationException("Template name must be a relative path.");
        }

        var basePathFull = Path.GetFullPath(_basePath);
        var candidatePath = Path.GetFullPath(Path.Combine(basePathFull, templateName));

        if (!IsUnderBasePath(basePathFull, candidatePath))
        {
            throw new InvalidOperationException("Template path is outside base path.");
        }

        if (!File.Exists(candidatePath))
        {
            throw new FileNotFoundException($"Template not found: {candidatePath}");
        }
        
        var template = await File.ReadAllTextAsync(candidatePath);

        foreach (var param in parameters)
        {
            // HTML encode to prevent injection
            var encodedValue = System.Net.WebUtility.HtmlEncode(param.Value);
            template = template.Replace($"{{{{{param.Key}}}}}", encodedValue);
        }

        return template;
    }

    private static bool IsUnderBasePath(string basePathFull, string candidatePath)
    {
        var normalizedBase = basePathFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return candidatePath.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase);
    }
}
