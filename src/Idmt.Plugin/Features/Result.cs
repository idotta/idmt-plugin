using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Features;

public class Result
{
    public bool IsSuccess { get; init; }
    public string? ErrorMessage { get; init; }
    public int StatusCode { get; init; } = StatusCodes.Status200OK;

    public static Result Success(int statusCode = StatusCodes.Status200OK)
    {
        return new Result { IsSuccess = true, StatusCode = statusCode };
    }

    public static Result Failure(string errorMessage, int statusCode = StatusCodes.Status400BadRequest)
    {
        return new Result { IsSuccess = false, ErrorMessage = errorMessage, StatusCode = statusCode };
    }

    public static Result<T> Success<T>(T value, int statusCode = StatusCodes.Status200OK)
    {
        return new Result<T> { IsSuccess = true, Value = value, StatusCode = statusCode };
    }

    public static Result<T> Failure<T>(string errorMessage, int statusCode = StatusCodes.Status400BadRequest)
    {
        return new Result<T> { IsSuccess = false, ErrorMessage = errorMessage, StatusCode = statusCode };
    }
}

public class Result<T> : Result
{
    public T? Value { get; init; }
}