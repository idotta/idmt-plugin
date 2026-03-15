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

public static class UpdateUser
{
    public sealed record UpdateUserRequest(bool IsActive);

    public interface IUpdateUserHandler
    {
        Task<ErrorOr<Success>> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserHandler(
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService,
        ILogger<UpdateUserHandler> logger) : IUpdateUserHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
                if (appUser == null)
                {
                    return IdmtErrors.User.NotFound;
                }

                var userRoles = await userManager.GetRolesAsync(appUser);

                if (!tenantAccessService.CanManageUser(userRoles))
                {
                    return IdmtErrors.User.InsufficientPermissions;
                }

                appUser.IsActive = request.IsActive;

                var result = await userManager.UpdateAsync(appUser);
                if (!result.Succeeded)
                {
                    return IdmtErrors.User.UpdateFailed;
                }
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Exception occurred while updating user {UserId}", userId);
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapUpdateUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPut("/users/{userId:guid}", async Task<Results<Ok, NotFound, ForbidHttpResult, BadRequest, InternalServerError>> (
            [FromRoute] Guid userId,
            [FromBody] UpdateUserRequest request,
            [FromServices] IUpdateUserHandler handler,
            HttpContext context) =>
        {
            var result = await handler.HandleAsync(userId, request, cancellationToken: context.RequestAborted);
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
        .WithSummary("Activate/Deactivate user")
        .WithDescription("Activate/Deactivate a user within the same tenant (Admin/System only)");
    }
}
