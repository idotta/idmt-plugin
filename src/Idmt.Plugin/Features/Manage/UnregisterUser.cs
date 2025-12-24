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
    public interface IUnregisterUserHandler
    {
        Task<Result> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class UnregisterUserHandler(
        ICurrentUserService currentUserService,
        ILogger<UnregisterUserHandler> logger,
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService) : IUnregisterUserHandler
    {
        public async Task<Result> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                logger.LogDebug("Unregistering user {UserId} requested by {CurrentUserId}", userId, currentUserService.UserId);
                var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
                if (appUser is null)
                {
                    return Result.Failure("User not found", StatusCodes.Status404NotFound);
                }

                var userRoles = await userManager.GetRolesAsync(appUser);

                if (!tenantAccessService.CanManageUser(userRoles))
                {
                    return Result.Failure("Insufficient permissions to delete this user.", StatusCodes.Status403Forbidden);
                }

                var result = await userManager.DeleteAsync(appUser);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    logger.LogError("Failed to unregister user {UserId}: {Errors}", userId, errors);
                    return Result.Failure(errors, StatusCodes.Status400BadRequest);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Exception occurred while unregistering user {UserId}", userId);
                return Result.Failure($"An error occurred while unregistering the user: {ex.Message}", StatusCodes.Status500InternalServerError);
            }

            return Result.Success();
        }
    }

    public static RouteHandlerBuilder MapUnregisterUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}", async Task<Results<Ok, NotFound, ForbidHttpResult, BadRequest, InternalServerError>> (
            [FromRoute] Guid userId,
            ClaimsPrincipal user,
            [FromServices] IUnregisterUserHandler handler,
            HttpContext context) =>
        {
            var result = await handler.HandleAsync(userId, cancellationToken: context.RequestAborted);
            if (!result.IsSuccess)
            {
                return result.StatusCode switch
                {
                    StatusCodes.Status404NotFound => TypedResults.NotFound(),
                    StatusCodes.Status403Forbidden => TypedResults.Forbid(),
                    StatusCodes.Status400BadRequest => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Delete user")
        .WithDescription("Delete a user within the same tenant (Admin/System only)");
    }
}