using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface IExternalLoginService<TUser> where TUser : class, IAuthUser
{
    Task<Result<RefreshTokenDto>> ExternalLoginWithGoogle(string idToken, string? expectedNonce = null);
}
