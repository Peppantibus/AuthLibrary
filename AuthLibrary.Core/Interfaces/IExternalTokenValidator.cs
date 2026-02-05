using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface IExternalTokenValidator
{
    Task<ExternalUserInfo> ValidateGoogleIdToken(string idToken);
}
