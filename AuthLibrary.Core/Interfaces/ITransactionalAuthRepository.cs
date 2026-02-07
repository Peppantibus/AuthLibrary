namespace AuthLibrary.Interfaces;

public interface ITransactionalAuthRepository<TUser> where TUser : class, IAuthUser
{
    Task ExecuteInTransactionAsync(Func<Task> operation);
}
