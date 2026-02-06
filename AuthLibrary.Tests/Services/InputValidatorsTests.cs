using AuthLibrary.Validation;

namespace AuthLibrary.Tests.Services;

public class InputValidatorsTests
{
    [Fact]
    public void ValidateLogin_WithValidInput_ReturnsSuccess()
    {
        var result = InputValidators.ValidateLogin("user.test", "Valid123!");

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateLogin_WithInvalidUsernameFormat_ReturnsFailure()
    {
        var result = InputValidators.ValidateLogin("user test", "Valid123!");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("username non valido");
    }

    [Fact]
    public void ValidateLogin_WithTooLongUsername_ReturnsFailure()
    {
        var username = new string('a', 101);

        var result = InputValidators.ValidateLogin(username, "Valid123!");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("username troppo lungo");
    }

    [Fact]
    public void ValidateLogin_WithTooLongPassword_ReturnsFailure()
    {
        var password = new string('A', 257);

        var result = InputValidators.ValidateLogin("user", password);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("password troppo lunga");
    }

    [Fact]
    public void ValidateResetPassword_WithInvalidTokenLength_ReturnsFailure()
    {
        var body = new ResetPasswordDto
        {
            Token = "too-short-token",
            Password = "Valid123!",
            ConfirmPassword = "Valid123!"
        };

        var result = InputValidators.ValidateResetPassword(body);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("token non valido");
    }

    [Fact]
    public void ValidateResetPassword_WithInvalidTokenFormat_ReturnsFailure()
    {
        var body = new ResetPasswordDto
        {
            Token = $"{new string('A', 31)},",
            Password = "Valid123!",
            ConfirmPassword = "Valid123!"
        };

        var result = InputValidators.ValidateResetPassword(body);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("token non valido");
    }

    [Fact]
    public void ValidateResetPassword_WithTooLongPassword_ReturnsFailure()
    {
        var body = new ResetPasswordDto
        {
            Token = new string('A', 32),
            Password = new string('A', 257),
            ConfirmPassword = "Valid123!"
        };

        var result = InputValidators.ValidateResetPassword(body);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("password troppo lunga");
    }

    [Fact]
    public void ValidateEmail_WithValidEmail_ReturnsSuccess()
    {
        var result = InputValidators.ValidateEmail("user@example.com");

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateEmail_WithInvalidEmail_ReturnsFailure()
    {
        var result = InputValidators.ValidateEmail("not-an-email");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("email non valida");
    }

    [Fact]
    public void ValidateUsername_WithInvalidCharacters_ReturnsFailure()
    {
        var result = InputValidators.ValidateUsername("name with space");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("username non valido");
    }
}
