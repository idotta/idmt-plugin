using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class GetUserInfo
{
    public sealed record GetUserInfoResponse(
        string Id,
        string Email,
        string UserName,
        bool EmailConfirmed,
        string TenantId,
        string Role,
        DateTime? LastLoginAt,
        bool IsActive
    );

    public interface IGetUserInfoHandler
    {
        Task<GetUserInfoResponse?> HandleAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserInfoHandler(UserManager<IdmtUser> userManager) : IGetUserInfoHandler
    {
        public async Task<GetUserInfoResponse?> HandleAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default)
        {
            var userEmail = user.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(userEmail))
            {
                return null;
            }

            var appUser = await userManager.FindByEmailAsync(userEmail);
            if (appUser == null || !appUser.IsActive)
            {
                return null;
            }

            var role = (await userManager.GetRolesAsync(appUser)).FirstOrDefault() ?? IdmtDefaultRoleTypes.TenantUser;

            return new GetUserInfoResponse(
                appUser.Id.ToString(),
                appUser.Email!,
                appUser.UserName!,
                appUser.EmailConfirmed,
                appUser.TenantId,
                role,
                appUser.LastLoginAt,
                appUser.IsActive
            );
        }
    }
}