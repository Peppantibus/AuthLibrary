using AuthLibrary.Models;

namespace AuthLibrary.Interfaces;

public interface IAuthRepository<TUser> where TUser : class, IAuthUser
{
    Task<TUser?> GetUserByUsernameAsync(string username);
    Task<TUser?> GetUserByEmailAsync(string email);
    Task<TUser?> GetUserByIdAsync(string id); // Added for ResetPassword
    Task<bool> UserExistsAsync(string username, string email);
    Task AddUserAsync(TUser user);
    Task UpdateUserAsync(TUser user); // For password update, email verify
    Task RemoveUserAsync(TUser user); // For rollback on email failure

    // Tokens
    Task AddEmailVerifiedTokenAsync(EmailVerifiedToken token);
    Task<EmailVerifiedToken?> GetEmailVerifiedTokenAsync(string tokenHash);
    Task RemoveEmailVerifiedTokenAsync(EmailVerifiedToken token);
    Task RemoveEmailVerifiedTokensByUserIdAsync(string userId);

    Task AddPasswordResetTokenAsync(PasswordResetToken token);
    Task<PasswordResetToken?> GetPasswordResetTokenAsync(string tokenHash);
    Task RemovePasswordResetTokenAsync(PasswordResetToken token);
    Task RemovePasswordResetTokensByUserIdAsync(string userId);

    // Refresh Tokens
    Task AddRefreshTokenAsync(RefreshToken token);
    Task<RefreshToken?> GetRefreshTokenAsync(string token);
    Task UpdateRefreshTokenAsync(RefreshToken token);
    Task RemoveRefreshTokensByUserIdAsync(string userId);
    
    Task SaveChangesAsync();
}
