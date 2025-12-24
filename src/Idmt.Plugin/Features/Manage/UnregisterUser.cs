using System.Security.Claims;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Manage;

public static class UnregisterUser
{
    public sealed record UnregisterUserResponse(bool Success, List<string>? Errors = null, int StatusCode = StatusCodes.Status200OK);

    public interface IUnregisterUserHandler
    {
        Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class UnregisterUserHandler(
        ICurrentUserService currentUserService,
        ILogger<UnregisterUserHandler> logger,
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService) : IUnregisterUserHandler
    {
        public async Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            logger.LogDebug("Unregistering user {UserId} requested by {CurrentUserId}", userId, currentUserService.UserId);
            var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
            if (appUser is null)
            {
                return new UnregisterUserResponse(false, ["User not found"], StatusCodes.Status404NotFound);
            }

            var userRoles = await userManager.GetRolesAsync(appUser);

            if (!tenantAccessService.CanManageUser(userRoles))
            {
                return new UnregisterUserResponse(false, ["Insufficient permissions to delete this user."], StatusCodes.Status403Forbidden);
            }

            var result = await userManager.DeleteAsync(appUser);

            return new UnregisterUserResponse(
                result.Succeeded,
                [.. result.Errors.Select(e => e.Description)],
                result.Succeeded ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest);
        }
    }

    public static RouteHandlerBuilder MapUnregisterUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}", async Task<Results<Ok<UnregisterUserResponse>, ProblemHttpResult>> (
            [FromRoute] Guid userId,
            ClaimsPrincipal user,
            [FromServices] IUnregisterUserHandler handler,
            HttpContext context) =>
        {
            var result = await handler.HandleAsync(userId, cancellationToken: context.RequestAborted);
            if (!result.Success)
            {
                var errorMessage = result.Errors is not null ? string.Join("; ", result.Errors) : "Failed to unregister user";
                return TypedResults.Problem(errorMessage, statusCode: result.StatusCode);
            }
            return TypedResults.Ok(result);
        })
        .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Delete user")
        .WithDescription("Delete a user within the same tenant (Admin/System only)");
    }
}