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

    /// <summary>
    /// Interface for logout operations
    /// </summary>
    public interface ILogoutHandler
    {
        /// <summary>
        /// Handles user logout
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        Task HandleAsync(CancellationToken cancellationToken = default);
    }

    internal sealed class LogoutHandler(ILogger<LogoutHandler> logger, SignInManager<IdmtUser> signInManager)
    : ILogoutHandler
    {
        public async Task HandleAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await signInManager.SignOutAsync();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during logout");
                throw;
            }
        }
    }

    public static RouteHandlerBuilder MapLogoutEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/logout", async Task<NoContent> (
            [FromServices] ILogoutHandler logoutHandler,
            CancellationToken cancellationToken = default) =>
        {
            await logoutHandler.HandleAsync(cancellationToken);
            return TypedResults.NoContent();
        })
        .WithSummary("Logout user")
        .WithDescription("Logout user and invalidate bearer token or cookie");
    }
}