namespace AuthLibrary.Models;

public class Result
{
    public bool IsSuccess { get; }
    public string Error { get; }
    public string? ErrorCode { get; }
    public bool IsFailure => !IsSuccess;

    protected Result(bool isSuccess, string error, string? errorCode = null)
    {
        if (isSuccess && error != string.Empty)
            throw new InvalidOperationException();
        if (!isSuccess && error == string.Empty)
            throw new InvalidOperationException();

        IsSuccess = isSuccess;
        Error = error;
        ErrorCode = errorCode;
    }

    public static Result Fail(string message, string? errorCode = null)
    {
        return new Result(false, message, errorCode);
    }

    public static Result<T> Fail<T>(string message, string? errorCode = null)
    {
        return new Result<T>(default!, false, message, errorCode);
    }

    public static Result Ok()
    {
        return new Result(true, string.Empty);
    }
    
    public static Result<T> Ok<T>(T value)
    {
        return new Result<T>(value, true, string.Empty);
    }
}

public class Result<T> : Result
{
    public T Value { get; }

    protected internal Result(T value, bool isSuccess, string error, string? errorCode = null)
        : base(isSuccess, error, errorCode)
    {
        Value = value;
    }
}
