namespace AuthLibrary.Tests.Services;

public class PasswordValidatorTests
{
    private readonly IPasswordValidator _validator;

    public PasswordValidatorTests()
    {
        _validator = new DefaultPasswordValidator();
    }

    [Fact]
    public void IsValid_WithValidPassword_ReturnsTrue()
    {
        // Arrange
        var password = "SecurePass123!";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeTrue();
        errorMessage.Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void IsValid_WithEmptyOrNullPassword_ReturnsFalse(string password)
    {
        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password non può essere vuota");
    }

    [Theory]
    [InlineData("Short1!")]
    [InlineData("Abc123!")]
    public void IsValid_WithPasswordShorterThan8Characters_ReturnsFalse(string password)
    {
        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password deve contenere almeno 8 caratteri");
    }

    [Fact]
    public void IsValid_WithoutUppercaseLetter_ReturnsFalse()
    {
        // Arrange
        var password = "lowercase123!";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password deve contenere almeno una lettera maiuscola");
    }

    [Fact]
    public void IsValid_WithoutLowercaseLetter_ReturnsFalse()
    {
        // Arrange
        var password = "UPPERCASE123!";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password deve contenere almeno una lettera minuscola");
    }

    [Fact]
    public void IsValid_WithoutDigit_ReturnsFalse()
    {
        // Arrange
        var password = "NoNumbersHere!";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password deve contenere almeno un numero");
    }

    [Fact]
    public void IsValid_WithoutSpecialCharacter_ReturnsFalse()
    {
        // Arrange
        var password = "NoSpecialChar123";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Be("La password deve contenere almeno un carattere speciale");
    }

    [Theory]
    [InlineData("MyP@ssw0rd")]
    [InlineData("SuperSecure123!")]
    [InlineData("C0mpl3x#Pass")]
    [InlineData("Test1234!@#$")]
    public void IsValid_WithVariousValidPasswords_ReturnsTrue(string password)
    {
        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeTrue();
        errorMessage.Should().BeEmpty();
    }

    [Fact]
    public void IsValid_WithMinimumRequirements_ReturnsTrue()
    {
        // Arrange - Exactly 8 chars with all required types
        var password = "Abcd123!";

        // Act
        var result = _validator.IsValid(password, out var errorMessage);

        // Assert
        result.Should().BeTrue();
        errorMessage.Should().BeEmpty();
    }
}
