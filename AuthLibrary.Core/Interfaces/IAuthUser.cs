namespace AuthLibrary.Interfaces;

public interface IAuthUser
{
    string Id { get; set; }
    string Username { get; set; }
    string Email { get; set; }
    string Password { get; set; } 
    string Salt { get; set; }
    bool EmailVerified { get; set; }
    DateTime? PasswordUpdatedAt { get; set; }
    string Name { get; set; }
    string LastName { get; set; }
}
