using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface IPasswordFlowService<TUser> where TUser : class, IAuthUser
{
    Task<Result<string>> RecoveryPassword(string email);
    Task<Result<bool>> ResetPasswordRedirect(string token);
    Task<Result<bool>> ResetPassword(ResetPasswordDto body);
}
