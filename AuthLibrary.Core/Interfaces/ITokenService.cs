using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface ITokenService<TUser> where TUser : IAuthUser
{
    Task<RefreshTokenDto> RefreshToken(string token);
    Task<Result<RefreshTokenDto>> TryRefreshToken(string token);
    string GenerateRefreshToken();
    Task<RefreshTokenIssueResult> CreateRefreshToken(TUser user);
    AccessTokenResult GenerateAccessToken(TUser user);
}
