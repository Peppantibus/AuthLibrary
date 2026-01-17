namespace Chat.AuthLibrary.Enum;

public enum AccountStatus
{
    Pending = 0,      // Account created but email not verified
    Active = 1,       // Email verified, account fully active
    Suspended = 2,    // Account suspended by admin
    Deleted = 3       // Soft delete
}
