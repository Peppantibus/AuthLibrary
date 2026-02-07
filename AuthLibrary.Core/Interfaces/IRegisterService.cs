using AuthLibrary.Models;

namespace AuthLibrary.Interfaces;

public interface IRegisterService<TUser> where TUser : class, IAuthUser
{
    Task<Result> AddUser(TUser user);
}
