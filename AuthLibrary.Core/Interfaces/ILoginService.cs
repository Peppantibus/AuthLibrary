using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface ILoginService<TUser> where TUser : class, IAuthUser
{
    Task<Result<RefreshTokenDto>> Login(string username, string password);
}
