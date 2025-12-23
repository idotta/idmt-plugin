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

namespace Idmt.Plugin.Features.Manage;

public static class UpdateUser
{
    public sealed record UpdateUserRequest(bool IsActive);
    public sealed record UpdateUserResponse(bool Success, string? ErrorMessage = null);

    public interface IUpdateUserHandler
    {
        Task<UpdateUserResponse> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserHandler(
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService) : IUpdateUserHandler
    {
        public async Task<UpdateUserResponse> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
            if (appUser == null)
            {
                return new UpdateUserResponse(false, "User not found");
            }

            var userRoles = await userManager.GetRolesAsync(appUser);

            if (!tenantAccessService.CanManageUser(userRoles))
            {
                return new UpdateUserResponse(false, "Insufficient permissions to update this user.");
            }

            appUser.IsActive = request.IsActive;

            var result = await userManager.UpdateAsync(appUser);
            if (!result.Succeeded)
            {
                return new UpdateUserResponse(false, "Failed to update user");
            }
            return new UpdateUserResponse(true);
        }
    }

    public static RouteHandlerBuilder MapUpdateUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPut("/users/{userId:guid}", async Task<Results<Ok, NotFound, ProblemHttpResult>> (
            [FromRoute] Guid userId,
            [FromBody] UpdateUserRequest request,
            [FromServices] IUpdateUserHandler handler,
            HttpContext context) =>
        {
            var result = await handler.HandleAsync(userId, request, cancellationToken: context.RequestAborted);
            if (!result.Success)
            {
                return TypedResults.Problem(result.ErrorMessage, statusCode: StatusCodes.Status403Forbidden);
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Activate/Deactivate user")
        .WithDescription("Activate/Deactivate a user within the same tenant (Admin/System only)");
    }
}