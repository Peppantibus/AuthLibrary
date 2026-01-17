using Chat.AuthLibrary.Models;
using Chat.AuthLibrary.Models.Dto.Auth;

namespace Chat.AuthLibrary.Interfaces;

public interface IAuthService<TUser> where TUser : IAuthUser
{
    Task<Result<RefreshTokenDto>> Login(string username, string password);
    Task<Result> AddUser(TUser user);
    Task<Result<string>> RecoveryPassword(string email); 
    Task<Result<bool>> ResetPasswordRedirect(string token); 
    Task<Result<bool>> ResetPassword(ResetPasswordDto body);
    Task<Result<bool>> VerifyMail(string token);
    Task<Result> ResendVerificationEmail(string email);
}
