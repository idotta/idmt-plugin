using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Auth.Manage;

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
}