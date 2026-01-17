using System.IO;
using AuthLibrary.Tests.Helpers;
using MockFactory = AuthLibrary.Tests.Helpers.MockFactory;

namespace AuthLibrary.Tests.Services;

public class MailTemplateServiceTests
{
    [Fact]
    public async Task RenderTemplateAsync_ReplacesPlaceholdersAndEncodesValues()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), "authlib-templates-" + Guid.NewGuid());
        Directory.CreateDirectory(tempDir);
        var templatePath = Path.Combine(tempDir, "VerifyEmail.html");
        await File.WriteAllTextAsync(templatePath, "Hello {{username}}, link: {{url}}");

        try
        {
            var settings = MockFactory.CreateOptions(new TemplateSettings { BasePath = tempDir });
            var service = new MailTemplateService(settings);

            var parameters = new Dictionary<string, string>
            {
                { "username", "<admin>" },
                { "url", "https://example.com/reset?x=1&y=2" }
            };

            // Act
            var result = await service.RenderTemplateAsync("VerifyEmail.html", parameters);

            // Assert
            result.Should().Contain("Hello &lt;admin&gt;");
            result.Should().Contain("https://example.com/reset?x=1&amp;y=2");
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task RenderTemplateAsync_WhenTemplateMissing_Throws()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), "authlib-templates-" + Guid.NewGuid());
        Directory.CreateDirectory(tempDir);

        try
        {
            var settings = MockFactory.CreateOptions(new TemplateSettings { BasePath = tempDir });
            var service = new MailTemplateService(settings);

            // Act
            var act = async () => await service.RenderTemplateAsync("missing.html", new Dictionary<string, string>());

            // Assert
            await act.Should().ThrowAsync<FileNotFoundException>();
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
