using AuthLibrary.Tests.Helpers;
using System.Security.Cryptography;
using System.Text;

using MockFactory = AuthLibrary.Tests.Helpers.MockFactory;

namespace AuthLibrary.Tests.Services;

public class AuthServiceBasicTests
{
    private readonly Mock<IAuthRepository<TestUser>> _repositoryMock;
    private readonly Mock<ITokenService<TestUser>> _tokenServiceMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly Mock<IMailService> _mailServiceMock;
    private readonly Mock<IMailTemplateService> _templateServiceMock;
    private readonly Mock<ILogger<AuthService<TestUser>>> _loggerMock;
    private readonly Mock<IPasswordValidator> _passwordValidatorMock;
    private readonly IOptions<SecuritySettings> _securitySettings;
    private readonly IOptions<AuthSettings> _authSettings;
    private readonly IOptions<MailSettings> _mailSettings;
    private readonly AuthService<TestUser> _authService;

    public AuthServiceBasicTests()
    {
        _repositoryMock = MockFactory.CreateAuthRepository<TestUser>();
        _tokenServiceMock = MockFactory.CreateTokenService<TestUser>();
        _rateLimitServiceMock = MockFactory.CreateRateLimitService();
        _mailServiceMock = MockFactory.CreateMailService();
        _templateServiceMock = new Mock<IMailTemplateService>();
        _loggerMock = MockFactory.CreateLogger<AuthService<TestUser>>();
        _passwordValidatorMock = MockFactory.CreatePasswordValidator();

        _securitySettings = MockFactory.CreateOptions(MockFactory.CreateSecuritySettings());
        _authSettings = MockFactory.CreateOptions(new AuthSettings { FrontendUrl = "https://test.com" });
        _mailSettings = MockFactory.CreateOptions(MockFactory.CreateMailSettings());

        _authService = new AuthService<TestUser>(
            _repositoryMock.Object,
            _securitySettings,
            _mailServiceMock.Object,
            _tokenServiceMock.Object,
            _rateLimitServiceMock.Object,
            _templateServiceMock.Object,
            _authSettings,
            _mailSettings,
            _loggerMock.Object,
            _passwordValidatorMock.Object
        );
    }

    #region Login Tests

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsSuccessWithTokens()
    {
        // Arrange
        var username = "testuser";
        var password = "ValidPassword123!";
        var salt = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        
        // Generate proper Argon2 hash to match the service hashing
        var saltBytes = Convert.FromBase64String(salt);
        var pepper = _securitySettings.Value.Pepper;
        var passwordHash = GenerateArgon2Hash(password, saltBytes, pepper);

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithEmail("test@example.com")
            .WithPassword(passwordHash) 
            .WithSalt(salt)
            .AsVerified()
            .Build();

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);
        
        var expectedAccessToken = new AccessTokenResult { Token = "jwt-token", ExpiresInSeconds = 900 };
        var expectedRefreshToken = new RefreshTokenIssueResult
        {
            PlainToken = "refresh-token",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            UserId = user.Id
        };

        _tokenServiceMock.Setup(x => x.GenerateAccessToken(user))
            .Returns(expectedAccessToken);
        _tokenServiceMock.Setup(x => x.CreateRefreshToken(user))
            .ReturnsAsync(expectedRefreshToken);
        _rateLimitServiceMock.Setup(x => x.Reset(RateLimitRequestType.Login, username))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().NotBeNull();
        result.Value.AccessToken.Token.Should().Be("jwt-token");
        result.Value.NewRefreshToken.Should().Be("refresh-token");

        _rateLimitServiceMock.Verify(x => x.Reset(RateLimitRequestType.Login, username), Times.Once);
    }

    [Fact]
    public async Task Login_WithInvalidPassword_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword123!";
        var salt = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var saltBytes = Convert.FromBase64String(salt);
        var pepper = _securitySettings.Value.Pepper;
        var passwordHash = GenerateArgon2Hash(correctPassword, saltBytes, pepper);

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithPassword(passwordHash)
            .WithSalt(salt)
            .AsVerified()
            .Build();


        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.Login(username, wrongPassword);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WithNonExistentUser_ReturnsFailure()
    {
        // Arrange
        var username = "nonexistent";
        var password = "Password123!";

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync((TestUser?)null);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WithUnverifiedEmail_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var password = "Password123!";

        var user = TestDataBuilder.User()
            .WithUsername(username)
            .WithEmailVerified(false) // Not verified
            .Build();

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Login, username))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.GetUserByUsernameAsync(username))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Credenziali non valide");
    }

    [Fact]
    public async Task Login_WhenRateLimited_ReturnsFailure()
    {
        // Arrange
        var username = "testuser";
        var password = "Password123!";

        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Login, username))
            .ReturnsAsync(true); // Rate limit reached

        // Act
        var result = await _authService.Login(username, password);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("bloccato");
    }

    #endregion

    #region Configuration Tests

    [Fact]
    public void Constructor_WithEmptyPepper_Throws()
    {
        // Arrange
        var badSecuritySettings = MockFactory.CreateOptions(new SecuritySettings { Pepper = "" });

        // Act
        var act = () => new AuthService<TestUser>(
            _repositoryMock.Object,
            badSecuritySettings,
            _mailServiceMock.Object,
            _tokenServiceMock.Object,
            _rateLimitServiceMock.Object,
            _templateServiceMock.Object,
            _authSettings,
            _mailSettings,
            _loggerMock.Object,
            _passwordValidatorMock.Object
        );

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Pepper*");
    }

    #endregion

    #region Register Tests

    [Fact]
    public async Task AddUser_WithValidUser_ReturnsOkAndSendsVerificationEmail()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithEmail("test@example.com")
            .WithUsername("testuser")
            .WithPassword("ValidPassword123!")
            .Build();

        string passwordError = string.Empty;
        _passwordValidatorMock.Setup(x => x.IsValid(user.Password, out passwordError))
            .Returns(true);

        _rateLimitServiceMock.Setup(x => x.IsBlocked(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsInCooldown(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.StartCooldown(It.IsAny<RateLimitRequestType>(), It.IsAny<string>(), It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        _repositoryMock.Setup(x => x.UserExistsAsync(user.Username, user.Email))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.AddUserAsync(user))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.AddEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        _templateServiceMock.Setup(x => x.RenderTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("<html>ok</html>");
        _mailServiceMock.Setup(x => x.SendAsync(It.IsAny<MailDto>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.AddUser(user);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        _repositoryMock.Verify(x => x.AddUserAsync(user), Times.Once);
        _repositoryMock.Verify(x => x.AddEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Exactly(2));
        _mailServiceMock.Verify(x => x.SendAsync(It.IsAny<MailDto>()), Times.Once);
        _rateLimitServiceMock.Verify(x => x.RegisterAttempted(RateLimitRequestType.Register, user.Email), Times.Once);
    }

    [Fact]
    public async Task AddUser_WhenRateLimited_ReturnsFailure()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithEmail("test@example.com")
            .WithPassword("ValidPassword123!")
            .Build();

        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(true);

        // Act
        var result = await _authService.AddUser(user);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("bloccato");
        _repositoryMock.Verify(x => x.AddUserAsync(It.IsAny<TestUser>()), Times.Never);
    }

    [Fact]
    public async Task AddUser_WhenUserExists_ReturnsFailure()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithEmail("test@example.com")
            .WithUsername("testuser")
            .WithPassword("ValidPassword123!")
            .Build();

        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.UserExistsAsync(user.Username, user.Email))
            .ReturnsAsync(true);

        // Act
        var result = await _authService.AddUser(user);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("utente");
        _repositoryMock.Verify(x => x.AddUserAsync(It.IsAny<TestUser>()), Times.Never);
        _passwordValidatorMock.Verify(x => x.IsValid(It.IsAny<string>(), out It.Ref<string>.IsAny), Times.Never);
    }

    [Fact]
    public async Task AddUser_WithWeakPassword_ReturnsFailure()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithEmail("test@example.com")
            .WithUsername("testuser")
            .WithPassword("weak")
            .Build();

        string passwordError = "weak password";
        _passwordValidatorMock.Setup(x => x.IsValid(user.Password, out passwordError))
            .Returns(false);

        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.Register, user.Email))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.UserExistsAsync(user.Username, user.Email))
            .ReturnsAsync(false);

        // Act
        var result = await _authService.AddUser(user);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("weak");
        _repositoryMock.Verify(x => x.AddUserAsync(It.IsAny<TestUser>()), Times.Never);
    }

    [Fact]
    public async Task AddUser_WhenEmailSendFails_RollsBackUserAndToken()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithId("user-1")
            .WithEmail("test@example.com")
            .WithUsername("testuser")
            .WithPassword("ValidPassword123!")
            .Build();

        string passwordError = string.Empty;
        _passwordValidatorMock.Setup(x => x.IsValid(user.Password, out passwordError))
            .Returns(true);

        _rateLimitServiceMock.Setup(x => x.IsBlocked(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsInCooldown(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(It.IsAny<RateLimitRequestType>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.StartCooldown(It.IsAny<RateLimitRequestType>(), It.IsAny<string>(), It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        _repositoryMock.Setup(x => x.UserExistsAsync(user.Username, user.Email))
            .ReturnsAsync(false);
        _repositoryMock.Setup(x => x.AddUserAsync(user))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.AddEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.RemoveUserAsync(user))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.RemoveEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        _templateServiceMock.Setup(x => x.RenderTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("<html>ok</html>");
        _mailServiceMock.Setup(x => x.SendAsync(It.IsAny<MailDto>()))
            .ThrowsAsync(new InvalidOperationException("smtp down"));

        // Act
        var result = await _authService.AddUser(user);

        // Assert
        result.IsSuccess.Should().BeFalse();
        _repositoryMock.Verify(x => x.RemoveUserAsync(user), Times.Once);
        _repositoryMock.Verify(x => x.RemoveEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Exactly(3));
    }

    #endregion

    #region Email Verification Tests

    [Fact]
    public async Task ResendVerificationEmail_WithUnverifiedUser_SendsEmailAndReturnsOk()
    {
        // Arrange
        var user = TestDataBuilder.User()
            .WithEmail("test@example.com")
            .WithUsername("testuser")
            .WithEmailVerified(false)
            .Build();

        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.VerifyEmail, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsInCooldown(RateLimitRequestType.VerifyEmail, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.VerifyEmail, user.Email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.StartCooldown(RateLimitRequestType.VerifyEmail, user.Email, It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        _repositoryMock.Setup(x => x.GetUserByEmailAsync(user.Email))
            .ReturnsAsync(user);
        _repositoryMock.Setup(x => x.RemoveEmailVerifiedTokensByUserIdAsync(user.Id))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.AddEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        _templateServiceMock.Setup(x => x.RenderTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("<html>ok</html>");
        _mailServiceMock.Setup(x => x.SendAsync(It.IsAny<MailDto>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.ResendVerificationEmail(user.Email);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        _repositoryMock.Verify(x => x.RemoveEmailVerifiedTokensByUserIdAsync(user.Id), Times.Once);
        _repositoryMock.Verify(x => x.AddEmailVerifiedTokenAsync(It.IsAny<EmailVerifiedToken>()), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
        _mailServiceMock.Verify(x => x.SendAsync(It.IsAny<MailDto>()), Times.Once);
    }

    [Fact]
    public async Task VerifyMail_WithValidToken_MarksEmailVerified()
    {
        // Arrange
        var token = "verify-token";
        var tokenHash = HashToken(token);

        var user = TestDataBuilder.User()
            .WithId("user-1")
            .WithEmail("test@example.com")
            .WithEmailVerified(false)
            .Build();

        var entry = new EmailVerifiedToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        _repositoryMock.Setup(x => x.GetEmailVerifiedTokenAsync(tokenHash))
            .ReturnsAsync(entry);
        _repositoryMock.Setup(x => x.GetUserByIdAsync(user.Id))
            .ReturnsAsync(user);
        _repositoryMock.Setup(x => x.UpdateUserAsync(It.IsAny<TestUser>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.RemoveEmailVerifiedTokensByUserIdAsync(user.Id))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.VerifyMail(token);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().BeTrue();
        _repositoryMock.Verify(x => x.UpdateUserAsync(It.Is<TestUser>(u => u.EmailVerified)), Times.Once);
        _repositoryMock.Verify(x => x.RemoveEmailVerifiedTokensByUserIdAsync(user.Id), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
    }

    #endregion

    #region Password Recovery Tests

    [Fact]
    public async Task RecoveryPassword_WithExistingUser_SendsResetEmail()
    {
        // Arrange
        var email = "test@example.com";
        var user = TestDataBuilder.User()
            .WithId("user-1")
            .WithEmail(email)
            .WithUsername("testuser")
            .Build();

        _rateLimitServiceMock.Setup(x => x.IsBlocked(RateLimitRequestType.ResetPassword, email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.IsInCooldown(RateLimitRequestType.ResetPassword, email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.RegisterAttempted(RateLimitRequestType.ResetPassword, email))
            .ReturnsAsync(false);
        _rateLimitServiceMock.Setup(x => x.StartCooldown(RateLimitRequestType.ResetPassword, email, It.IsAny<TimeSpan>()))
            .Returns(Task.CompletedTask);

        _repositoryMock.Setup(x => x.GetUserByEmailAsync(email))
            .ReturnsAsync(user);
        _repositoryMock.Setup(x => x.RemovePasswordResetTokensByUserIdAsync(user.Id))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.AddPasswordResetTokenAsync(It.IsAny<PasswordResetToken>()))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        _templateServiceMock.Setup(x => x.RenderTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("<html>ok</html>");
        _mailServiceMock.Setup(x => x.SendAsync(It.IsAny<MailDto>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.RecoveryPassword(email);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().Contain("reset");
        _repositoryMock.Verify(x => x.AddPasswordResetTokenAsync(It.IsAny<PasswordResetToken>()), Times.Once);
        _mailServiceMock.Verify(x => x.SendAsync(It.IsAny<MailDto>()), Times.Once);
    }

    [Fact]
    public async Task ResetPasswordRedirect_WithExpiredToken_ReturnsFalseAndRemovesToken()
    {
        // Arrange
        var token = "expired-token";
        var tokenHash = HashToken(token);

        var entry = new PasswordResetToken
        {
            UserId = "user-1",
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(-1)
        };

        _repositoryMock.Setup(x => x.GetPasswordResetTokenAsync(tokenHash))
            .ReturnsAsync(entry);
        _repositoryMock.Setup(x => x.RemovePasswordResetTokenAsync(entry))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.ResetPasswordRedirect(token);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().BeFalse();
        _repositoryMock.Verify(x => x.RemovePasswordResetTokenAsync(entry), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
    }

    [Fact]
    public async Task ResetPassword_WithValidToken_UpdatesPasswordAndReturnsTrue()
    {
        // Arrange
        var token = "valid-token";
        var tokenHash = HashToken(token);

        var user = TestDataBuilder.User()
            .WithId("user-1")
            .WithPassword("old-hash")
            .WithSalt("old-salt")
            .Build();

        var entry = new PasswordResetToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10)
        };

        var body = new ResetPasswordDto
        {
            Token = token,
            Password = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        string passwordError = string.Empty;
        _passwordValidatorMock.Setup(x => x.IsValid(body.Password, out passwordError))
            .Returns(true);

        _repositoryMock.Setup(x => x.GetPasswordResetTokenAsync(tokenHash))
            .ReturnsAsync(entry);
        _repositoryMock.Setup(x => x.GetUserByIdAsync(user.Id))
            .ReturnsAsync(user);
        _repositoryMock.Setup(x => x.RemovePasswordResetTokensByUserIdAsync(user.Id))
            .Returns(Task.CompletedTask);
        _repositoryMock.Setup(x => x.SaveChangesAsync())
            .Returns(Task.CompletedTask);

        TestUser? updatedUser = null;
        _repositoryMock.Setup(x => x.UpdateUserAsync(It.IsAny<TestUser>()))
            .Callback<TestUser>(u => updatedUser = u)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authService.ResetPassword(body);

        // Assert
        result.IsSuccess.Should().BeTrue(result.Error);
        result.Value.Should().BeTrue();
        updatedUser.Should().NotBeNull();
        updatedUser!.Password.Should().NotBe("old-hash");
        updatedUser.Salt.Should().NotBe("old-salt");
        updatedUser.PasswordUpdatedAt.Should().NotBeNull();
        _repositoryMock.Verify(x => x.RemovePasswordResetTokensByUserIdAsync(user.Id), Times.Once);
        _repositoryMock.Verify(x => x.UpdateUserAsync(It.IsAny<TestUser>()), Times.Once);
        _repositoryMock.Verify(x => x.SaveChangesAsync(), Times.Once);
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Generates Argon2 hash matching the AuthService implementation
    /// </summary>
    private static string GenerateArgon2Hash(string password, byte[] salt, string pepper)
    {
        var config = new Isopoh.Cryptography.Argon2.Argon2Config
        {
            Type = Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
            Version = Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
            TimeCost = 4,
            MemoryCost = 65536,
            Lanes = 4,
            Threads = 4,
            Password = System.Text.Encoding.UTF8.GetBytes(password + pepper),
            Salt = salt,
            HashLength = 32
        };

        using var argon2 = new Isopoh.Cryptography.Argon2.Argon2(config);
        using var hash = argon2.Hash();
        return Convert.ToBase64String(hash.Buffer);
    }

    private static string HashToken(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    #endregion
}
