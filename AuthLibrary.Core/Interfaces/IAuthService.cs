using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

/// <summary>
/// Public authentication contract exposed by AuthLibrary.
/// </summary>
public interface IAuthService<TUser> where TUser : class, IAuthUser
{
    /// <summary>
    /// Authenticates user credentials and issues access/refresh tokens.
    /// </summary>
    Task<Result<RefreshTokenDto>> Login(string username, string password);

    /// <summary>
    /// Registers a new user and starts email verification flow.
    /// </summary>
    Task<Result> AddUser(TUser user);

    /// <summary>
    /// Starts password recovery flow. Returns a generic success message.
    /// </summary>
    Task<Result<string>> RecoveryPassword(string email);

    /// <summary>
    /// Checks whether the reset token is valid and not expired.
    /// </summary>
    Task<Result<bool>> ResetPasswordRedirect(string token);

    /// <summary>
    /// Resets password using reset token.
    /// </summary>
    Task<Result<bool>> ResetPassword(ResetPasswordDto body);

    /// <summary>
    /// Verifies email token and marks account as verified.
    /// </summary>
    Task<Result<bool>> VerifyMail(string token);

    /// <summary>
    /// Sends verification email again with enumeration-safe response.
    /// </summary>
    Task<Result> ResendVerificationEmail(string email);

    /// <summary>
    /// Exchanges a Google ID token for local access/refresh tokens.
    /// expectedNonce can be used by caller flows that bind token to nonce.
    /// </summary>
    Task<Result<RefreshTokenDto>> ExternalLoginWithGoogle(string idToken, string? expectedNonce = null);
}
