using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class GetUserInfo
{
    public sealed record GetUserInfoResponse(
        string Id,
        string Email,
        string UserName,
        string Role,
        string TenantIdentifier,
        string TenantDisplayName
    );

    public interface IGetUserInfoHandler
    {
        Task<GetUserInfoResponse?> HandleAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserInfoHandler(UserManager<IdmtUser> userManager, IMultiTenantStore<IdmtTenantInfo> tenantStore) : IGetUserInfoHandler
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

            // Fail fast
            var role = (await userManager.GetRolesAsync(appUser)).FirstOrDefault() ?? throw new InvalidOperationException("User has no role assigned");
            var tenant = await tenantStore.GetAsync(appUser.TenantId) ?? throw new InvalidOperationException("Tenant not found");

            return new GetUserInfoResponse(
                appUser.Id.ToString(),
                appUser.Email ?? string.Empty,
                appUser.UserName ?? string.Empty,
                role ?? string.Empty,
                tenant.Identifier ?? string.Empty,
                tenant.DisplayName ?? string.Empty
            );
        }
    }
}