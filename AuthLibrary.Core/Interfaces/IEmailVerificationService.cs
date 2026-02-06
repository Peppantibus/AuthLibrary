using AuthLibrary.Models;

namespace AuthLibrary.Interfaces;

public interface IEmailVerificationService<TUser> where TUser : class, IAuthUser
{
    Task<Result> ResendVerificationEmail(string email);
    Task<Result<bool>> VerifyMail(string token);
}
