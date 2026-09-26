namespace OfficeSecurity.Server.Application.Common;

public enum ErrorKind
{
    Validation,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden,
}

public sealed record ServiceError(ErrorKind Kind, string Message)
{
    public static ServiceError Validation(string message) => new(ErrorKind.Validation, message);

    public static ServiceError NotFound(string message) => new(ErrorKind.NotFound, message);

    public static ServiceError Conflict(string message) => new(ErrorKind.Conflict, message);

    public static ServiceError Unauthorized(string message) => new(ErrorKind.Unauthorized, message);

    public static ServiceError Forbidden(string message) => new(ErrorKind.Forbidden, message);
}

/// <summary>Outcome of a service call: either a value or an error suitable to show to the user.</summary>
public sealed class Result<T>
{
    private Result(T? value, ServiceError? error)
    {
        Value = value;
        Error = error;
    }

    public T? Value { get; }

    public ServiceError? Error { get; }

    public bool IsSuccess => Error is null;

#pragma warning disable CA1000 // Factory methods on a generic result type are the clearest API here.
    public static Result<T> Success(T value) => new(value, null);

    public static Result<T> Failure(ServiceError error) => new(default, error);
#pragma warning restore CA1000

    public static implicit operator Result<T>(T value) => Success(value);

    public static implicit operator Result<T>(ServiceError error) => Failure(error);
}

/// <summary>Marker value for results that carry no data.</summary>
public readonly record struct Done
{
    public static readonly Done Value;
}
