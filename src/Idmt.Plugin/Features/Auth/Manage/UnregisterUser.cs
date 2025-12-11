using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class UnregisterUser
{
    public sealed record UnregisterUserResponse(bool Success, List<string>? Errors = null, int StatusCode = StatusCodes.Status200OK);

    public interface IUnregisterUserHandler
    {
        Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class UnregisterUserHandler(
        UserManager<IdmtUser> userManager,
        ITenantAccessService tenantAccessService) : IUnregisterUserHandler
    {
        public async Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
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
}