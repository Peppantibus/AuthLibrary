namespace AuthLibrary.Tests.Helpers;

/// <summary>
/// Test user implementation for testing purposes
/// </summary>
public class TestUser : IAuthUser
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public required string Salt { get; set; }
    public required bool EmailVerified { get; set; }
    public DateTime? PasswordUpdatedAt { get; set; }
    public required string Name { get; set; }
    public required string LastName { get; set; }
}

/// <summary>
/// Builder for creating test data following the Builder pattern
/// </summary>
public class TestDataBuilder
{
    public static TestUserBuilder User() => new();
    
    public static RefreshTokenBuilder RefreshToken() => new();
    
    public static EmailVerificationTokenBuilder EmailVerificationToken() => new();
    
    public static PasswordResetTokenBuilder PasswordResetToken() => new();
}

public class TestUserBuilder
{
    private string _id = Guid.NewGuid().ToString();
    private string _email = "test@example.com";
    private string _username = "testuser";
    private string _password = "hashed-password";
    private string _salt = "random-salt";
    private bool _emailVerified = false;
    private DateTime? _passwordUpdatedAt = null;
    private string _name = "Test";
    private string _lastName = "User";

    public TestUserBuilder WithId(string id)
    {
        _id = id;
        return this;
    }

    public TestUserBuilder WithEmail(string email)
    {
        _email = email;
        return this;
    }

    public TestUserBuilder WithUsername(string username)
    {
        _username = username;
        return this;
    }

    public TestUserBuilder WithPassword(string password)
    {
        _password = password;
        return this;
    }

    public TestUserBuilder WithSalt(string salt)
    {
        _salt = salt;
        return this;
    }

    public TestUserBuilder WithEmailVerified(bool verified)
    {
        _emailVerified = verified;
        return this;
    }

    public TestUserBuilder AsVerified()
    {
        _emailVerified = true;
        return this;
    }

    public TestUserBuilder WithPasswordUpdatedAt(DateTime? updatedAt)
    {
        _passwordUpdatedAt = updatedAt;
        return this;
    }

    public TestUserBuilder WithName(string name, string lastName)
    {
        _name = name;
        _lastName = lastName;
        return this;
    }

    public TestUser Build()
    {
        return new TestUser
        {
            Id = _id,
            Email = _email,
            Username = _username,
            Password = _password,
            Salt = _salt,
            EmailVerified = _emailVerified,
            PasswordUpdatedAt = _passwordUpdatedAt,
            Name = _name,
            LastName = _lastName
        };
    }
}

public class RefreshTokenBuilder
{
    private string _userId = Guid.NewGuid().ToString();
    private string _tokenHash = "hashed-token";
    private DateTime _expiresAt = DateTime.UtcNow.AddDays(7);
    private DateTime _createdAt = DateTime.UtcNow;
    private DateTime? _revokedAt = null;
    private string? _replacedByToken = null;

    public RefreshTokenBuilder WithToken(string token)
    {
        _replacedByToken = token;
        return this;
    }

    public RefreshTokenBuilder WithUserId(string userId)
    {
        _userId = userId;
        return this;
    }

    public RefreshTokenBuilder WithHashedToken(string hashedToken)
    {
        _tokenHash = hashedToken;
        return this;
    }

    public RefreshTokenBuilder WithTokenHash(string tokenHash)
    {
        _tokenHash = tokenHash;
        return this;
    }

    public RefreshTokenBuilder WithExpiry(DateTime expiry)
    {
        _expiresAt = expiry;
        return this;
    }

    public RefreshTokenBuilder AsExpired()
    {
        _expiresAt = DateTime.UtcNow.AddDays(-1);
        return this;
    }

    public RefreshTokenBuilder AsRevoked()
    {
        _revokedAt = DateTime.UtcNow;
        return this;
    }

    public RefreshToken Build()
    {
        return new RefreshToken
        {
            UserId = _userId,
            TokenHash = _tokenHash,
            CreatedAt = _createdAt,
            ExpiresAt = _expiresAt,
            RevokedAt = _revokedAt,
            ReplacedByToken = _replacedByToken
        };
    }
}

public class EmailVerificationTokenBuilder
{
    private string _token = "test-verification-token";
    private DateTime _expiry = DateTime.UtcNow.AddHours(24);

    public EmailVerificationTokenBuilder WithToken(string token)
    {
        _token = token;
        return this;
    }

    public EmailVerificationTokenBuilder WithExpiry(DateTime expiry)
    {
        _expiry = expiry;
        return this;
    }

    public EmailVerificationTokenBuilder AsExpired()
    {
        _expiry = DateTime.UtcNow.AddHours(-1);
        return this;
    }

    public (string token, DateTime expiry) Build()
    {
        return (_token, _expiry);
    }
}

public class PasswordResetTokenBuilder
{
    private string _token = "test-reset-token";
    private DateTime _expiry = DateTime.UtcNow.AddHours(1);

    public PasswordResetTokenBuilder WithToken(string token)
    {
        _token = token;
        return this;
    }

    public PasswordResetTokenBuilder WithExpiry(DateTime expiry)
    {
        _expiry = expiry;
        return this;
    }

    public PasswordResetTokenBuilder AsExpired()
    {
        _expiry = DateTime.UtcNow.AddHours(-1);
        return this;
    }

    public (string token, DateTime expiry) Build()
    {
        return (_token, _expiry);
    }
}
