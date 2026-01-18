using AuthLibrary.Models;
using AuthLibrary.Models.Dto.Auth;

namespace AuthLibrary.Validation;

public static class InputValidators
{
    public static Result ValidateLogin(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Result.Fail("username obbligatorio");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            return Result.Fail("password obbligatoria");
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

        if (string.IsNullOrWhiteSpace(body.Password))
        {
            return Result.Fail("password obbligatoria");
        }

        if (string.IsNullOrWhiteSpace(body.ConfirmPassword))
        {
            return Result.Fail("confirm password obbligatoria");
        }

        return Result.Ok();
    }
}
