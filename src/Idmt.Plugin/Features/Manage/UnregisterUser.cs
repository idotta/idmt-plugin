using System.Security.Claims;
using ErrorOr;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
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
        Task<ErrorOr<Success>> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class UnregisterUserHandler(
        ICurrentUserService currentUserService,
        ILogger<UnregisterUserHandler> logger,
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService) : IUnregisterUserHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                logger.LogDebug("Unregistering user {UserId} requested by {CurrentUserId}", userId, currentUserService.UserId);
                var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
                if (appUser is null)
                {
                    return IdmtErrors.User.NotFound;
                }

                var userRoles = await userManager.GetRolesAsync(appUser);

                if (!tenantAccessService.CanManageUser(userRoles))
                {
                    return IdmtErrors.User.InsufficientPermissions;
                }

                var result = await userManager.DeleteAsync(appUser);

                if (!result.Succeeded)
                {
                    var errors = string.Join("\n", result.Errors.Select(e => e.Description));
                    logger.LogError("Failed to unregister user {UserId}: {Errors}", userId, errors);
                    return IdmtErrors.User.DeletionFailed;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Exception occurred while unregistering user {UserId}", userId);
                return IdmtErrors.General.Unexpected;
            }

            return Result.Success;
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
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.NotFound => TypedResults.NotFound(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.Failure => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(IdmtAuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Delete user")
        .WithDescription("Delete a user within the same tenant (Admin/System only)");
    }
}
