using ErrorOr;
using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Errors;

public static class ErrorOrExtensions
{
    public static IResult ToHttpResult(this List<Error> errors)
    {
        if (errors.Count == 0)
            return TypedResults.InternalServerError();

        var firstError = errors[0];
        return firstError.Type switch
        {
            ErrorType.NotFound => TypedResults.NotFound(),
            ErrorType.Validation => TypedResults.BadRequest(),
            ErrorType.Unauthorized => TypedResults.Unauthorized(),
            ErrorType.Forbidden => TypedResults.Forbid(),
            _ => TypedResults.InternalServerError(),
        };
    }
}
