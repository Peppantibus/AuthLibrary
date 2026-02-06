using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace AuthLibrary.Validation;

public static class InputValidators
{
    private const int MaxUsernameLength = 100;
    private const int MaxEmailLength = 254;
    private const int MinTokenLength = 32;
    private const int MaxTokenLength = 1024;
    private const int MaxPasswordLength = 256;
    private static readonly Regex UsernameRegex = new("^[a-zA-Z0-9._@+-]+$", RegexOptions.Compiled);
    private static readonly Regex TokenRegex = new("^[A-Za-z0-9+/=_-]+$", RegexOptions.Compiled);

    public static Result ValidateLogin(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Result.Fail("username obbligatorio");
        }

        if (username.Length > MaxUsernameLength)
        {
            return Result.Fail("username troppo lungo");
        }

        if (!UsernameRegex.IsMatch(username))
        {
            return Result.Fail("username non valido");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            return Result.Fail("password obbligatoria");
        }

        if (password.Length > MaxPasswordLength)
        {
            return Result.Fail("password troppo lunga");
        }

        return Result.Ok();
    }

    public static Result ValidateResetPassword(ResetPasswordDto body)
    {
        if (body == null)
        {
            return Result.Fail("richiesta non valida");
        }

        if (string.IsNullOrWhiteSpace(body.Token))
        {
            return Result.Fail("token obbligatorio");
        }

        if (body.Token.Length < MinTokenLength || body.Token.Length > MaxTokenLength)
        {
            return Result.Fail("token non valido");
        }

        if (!TokenRegex.IsMatch(body.Token))
        {
            return Result.Fail("token non valido");
        }

        if (string.IsNullOrWhiteSpace(body.Password))
        {
            return Result.Fail("password obbligatoria");
        }

        if (body.Password.Length > MaxPasswordLength)
        {
            return Result.Fail("password troppo lunga");
        }

        if (string.IsNullOrWhiteSpace(body.ConfirmPassword))
        {
            return Result.Fail("confirm password obbligatoria");
        }

        if (body.ConfirmPassword.Length > MaxPasswordLength)
        {
            return Result.Fail("confirm password troppo lunga");
        }

        return Result.Ok();
    }

    public static Result ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return Result.Fail("email obbligatoria");
        }

        if (email.Length > MaxEmailLength)
        {
            return Result.Fail("email troppo lunga");
        }

        try
        {
            var parsed = new MailAddress(email);
            if (!string.Equals(parsed.Address, email, StringComparison.OrdinalIgnoreCase))
            {
                return Result.Fail("email non valida");
            }
        }
        catch
        {
            return Result.Fail("email non valida");
        }

        return Result.Ok();
    }

    public static Result ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Result.Fail("username obbligatorio");
        }

        if (username.Length > MaxUsernameLength)
        {
            return Result.Fail("username troppo lungo");
        }

        if (!UsernameRegex.IsMatch(username))
        {
            return Result.Fail("username non valido");
        }

        return Result.Ok();
    }
}
