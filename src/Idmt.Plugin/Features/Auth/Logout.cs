using ErrorOr;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class Logout
{
    public interface ILogoutHandler
    {
        Task<ErrorOr<Success>> HandleAsync(CancellationToken cancellationToken = default);
    }

    internal sealed class LogoutHandler(ILogger<LogoutHandler> logger, SignInManager<IdmtUser> signInManager)
        : ILogoutHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await signInManager.SignOutAsync();
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during logout");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapLogoutEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/logout", async Task<Results<NoContent, ProblemHttpResult>> (
            [FromServices] ILogoutHandler logoutHandler,
            CancellationToken cancellationToken = default) =>
        {
            var result = await logoutHandler.HandleAsync(cancellationToken);
            if (result.IsError)
            {
                return TypedResults.Problem(result.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError);
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization()
        .WithSummary("Logout user")
        .WithDescription("Logout user and invalidate bearer token or cookie");
    }
}