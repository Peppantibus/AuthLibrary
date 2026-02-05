using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Interfaces;

public interface IExternalUserFactory<TUser> where TUser : class, IAuthUser
{
    TUser CreateFromExternal(ExternalUserInfo info);
}
