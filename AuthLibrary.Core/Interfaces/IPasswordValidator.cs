namespace AuthLibrary.Interfaces;

public interface IPasswordValidator
{
    bool IsValid(string password, out string errorMessage);
}

public class DefaultPasswordValidator : IPasswordValidator
{
    public const int MinPasswordLength = 8;
    public const int MaxPasswordLength = 256;

    public bool IsValid(string password, out string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "La password non puo essere vuota";
            return false;
        }

        if (password.Length < MinPasswordLength)
        {
            errorMessage = "La password deve contenere almeno 8 caratteri";
            return false;
        }

        if (password.Length > MaxPasswordLength)
        {
            errorMessage = "La password supera la lunghezza massima consentita";
            return false;
        }

        if (password.Any(char.IsControl))
        {
            errorMessage = "La password contiene caratteri non validi";
            return false;
        }

        if (!password.Any(char.IsUpper))
        {
            errorMessage = "La password deve contenere almeno una lettera maiuscola";
            return false;
        }

        if (!password.Any(char.IsLower))
        {
            errorMessage = "La password deve contenere almeno una lettera minuscola";
            return false;
        }

        if (!password.Any(char.IsDigit))
        {
            errorMessage = "La password deve contenere almeno un numero";
            return false;
        }

        if (!password.Any(c => !char.IsLetterOrDigit(c)))
        {
            errorMessage = "La password deve contenere almeno un carattere speciale";
            return false;
        }

        errorMessage = string.Empty;
        return true;
    }
}
