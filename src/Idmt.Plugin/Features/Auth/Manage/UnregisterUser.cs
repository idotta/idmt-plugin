using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class UnregisterUser
{
    public sealed record UnregisterUserResponse(bool Success, List<string>? Errors = null);

    public interface IUnregisterUserHandler
    {
        Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class UnregisterUserHandler(UserManager<IdmtUser> userManager) : IUnregisterUserHandler
    {
        public async Task<UnregisterUserResponse> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            var appUser = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
            if (appUser is null)
            {
                return new UnregisterUserResponse(false, ["User not found"]);
            }

            var result = await userManager.DeleteAsync(appUser);

            return new UnregisterUserResponse(
                result.Succeeded,
                [.. result.Errors.Select(e => e.Description)]);
        }
    }
}