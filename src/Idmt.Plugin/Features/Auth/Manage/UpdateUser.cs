using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class UpdateUser
{
    public sealed record UpdateUserRequest(bool IsActive);

    public interface IUpdateUserHandler
    {
        Task<bool> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserHandler(UserManager<IdmtUser> userManager) : IUpdateUserHandler
    {
        public async Task<bool> HandleAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
            if (appUser == null)
            {
                return false;
            }

            appUser.IsActive = request.IsActive;
            appUser.UpdatedAt = DateTime.UtcNow;
            appUser.UpdatedBy = appUser.Id;

            var result = await userManager.UpdateAsync(appUser);
            return result.Succeeded;
        }
    }
}