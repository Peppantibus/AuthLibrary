using AuthLibrary.Configuration;
using AuthLibrary.Interfaces;
using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthLibrary.Services;

public class AuthService<TUser> : IAuthService<TUser> where TUser : class, IAuthUser
{
    private readonly LoginService<TUser> _loginService;
    private readonly ExternalLoginService<TUser> _externalLoginService;
    private readonly RegisterService<TUser> _registerService;
    private readonly EmailVerificationService<TUser> _emailVerificationService;
    private readonly PasswordService<TUser> _passwordService;

    public AuthService(
        IAuthRepository<TUser> repository,
        IOptions<SecuritySettings> securitySettings,
        IMailService mailService,
        ITokenService<TUser> tokenService,
        IRateLimitService rateLimitService,
        IMailTemplateService templateService,
        IOptions<AuthSettings> authSettings,
        IOptions<MailSettings> mailSettings,
        ILogger<AuthService<TUser>> logger,
        IPasswordValidator passwordValidator,
        IExternalTokenValidator externalTokenValidator,
        IExternalUserFactory<TUser>? externalUserFactory = null)
    {
        var pepper = securitySettings.Value.Pepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("SecuritySettings:Pepper non configurato.");
        }

        var runtime = new AuthRuntime<TUser>(
            repository,
            pepper,
            mailService,
            tokenService,
            rateLimitService,
            templateService,
            authSettings.Value,
            mailSettings.Value,
            logger,
            passwordValidator,
            externalTokenValidator,
            externalUserFactory);

        _emailVerificationService = new EmailVerificationService<TUser>(runtime);
        _passwordService = new PasswordService<TUser>(runtime, _emailVerificationService);
        _registerService = new RegisterService<TUser>(runtime, _emailVerificationService);
        _loginService = new LoginService<TUser>(runtime);
        _externalLoginService = new ExternalLoginService<TUser>(runtime);
    }

    public Task<Result<RefreshTokenDto>> Login(string username, string password)
    {
        return _loginService.Login(username, password);
    }

    public Task<Result<RefreshTokenDto>> ExternalLoginWithGoogle(string idToken, string? expectedNonce = null)
    {
        return _externalLoginService.ExternalLoginWithGoogle(idToken, expectedNonce);
    }

    public Task<Result> AddUser(TUser user)
    {
        return _registerService.AddUser(user);
    }

    public Task<Result> ResendVerificationEmail(string email)
    {
        return _emailVerificationService.ResendVerificationEmail(email);
    }

    public Task<Result<string>> RecoveryPassword(string email)
    {
        return _passwordService.RecoveryPassword(email);
    }

    public Task<Result<bool>> ResetPasswordRedirect(string token)
    {
        return _passwordService.ResetPasswordRedirect(token);
    }

    public Task<Result<bool>> ResetPassword(ResetPasswordDto body)
    {
        return _passwordService.ResetPassword(body);
    }

    public Task<Result<bool>> VerifyMail(string token)
    {
        return _emailVerificationService.VerifyMail(token);
    }
}
