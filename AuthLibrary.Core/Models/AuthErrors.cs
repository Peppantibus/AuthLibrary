namespace AuthLibrary.Models;

public enum AuthErrorCode
{
    Unknown = 0,
    InvalidCredentials,
    UserBlocked,
    RateLimited,
    InvalidToken,
    TokenRefreshError,
    UserDataInvalid,
    EmailNotVerified,
    InvalidEmail,
    ExternalAccountExists,
    InvalidUser,
    UserCreationFailed,
    RegistrationInvalid,
    RecoveryError
}

public static class AuthErrorCatalog
{
    private static readonly IReadOnlyDictionary<AuthErrorCode, string> Messages = new Dictionary<AuthErrorCode, string>
    {
        [AuthErrorCode.Unknown] = "errore non specificato",
        [AuthErrorCode.InvalidCredentials] = "Credenziali non valide",
        [AuthErrorCode.UserBlocked] = "utente bloccato",
        [AuthErrorCode.RateLimited] = "utente bloccato per troppi tentativi",
        [AuthErrorCode.InvalidToken] = "token non valido",
        [AuthErrorCode.TokenRefreshError] = "errore durante il refresh token",
        [AuthErrorCode.UserDataInvalid] = "Errore dati utente",
        [AuthErrorCode.EmailNotVerified] = "email non verificata",
        [AuthErrorCode.InvalidEmail] = "email non valida",
        [AuthErrorCode.ExternalAccountExists] = "account gia esistente, collega google",
        [AuthErrorCode.InvalidUser] = "utente non valido",
        [AuthErrorCode.UserCreationFailed] = "impossibile creare utente",
        [AuthErrorCode.RegistrationInvalid] = "registrazione non valida",
        [AuthErrorCode.RecoveryError] = "errore durante il recupero"
    };

    public static string Message(AuthErrorCode code)
    {
        return Messages.TryGetValue(code, out var message) ? message : Messages[AuthErrorCode.Unknown];
    }

    public static Result Fail(AuthErrorCode code)
    {
        return Result.Fail(Message(code), code.ToString());
    }

    public static Result Fail(AuthErrorCode code, string message)
    {
        return Result.Fail(message, code.ToString());
    }

    public static Result<T> Fail<T>(AuthErrorCode code)
    {
        return Result.Fail<T>(Message(code), code.ToString());
    }

    public static Result<T> Fail<T>(AuthErrorCode code, string message)
    {
        return Result.Fail<T>(message, code.ToString());
    }
}
