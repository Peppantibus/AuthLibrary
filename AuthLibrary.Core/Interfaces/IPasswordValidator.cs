namespace Chat.AuthLibrary.Interfaces;

public interface IPasswordValidator
{
    bool IsValid(string password, out string errorMessage);
}

public class DefaultPasswordValidator : IPasswordValidator
{
    public bool IsValid(string password, out string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "La password non può essere vuota";
            return false;
        }

        if (password.Length < 8)
        {
            errorMessage = "La password deve contenere almeno 8 caratteri";
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
