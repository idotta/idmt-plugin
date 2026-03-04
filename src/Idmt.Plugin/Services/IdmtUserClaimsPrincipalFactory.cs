using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Constants;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

internal sealed class IdmtUserClaimsPrincipalFactory(
    UserManager<IdmtUser> userManager,
    RoleManager<IdmtRole> roleManager,
    IOptions<IdentityOptions> optionsAccessor,
    IMultiTenantStore<IdmtTenantInfo> tenantStore,
    IOptions<IdmtOptions> idmtOptions,
    ILogger<IdmtUserClaimsPrincipalFactory> logger)
    : UserClaimsPrincipalFactory<IdmtUser, IdmtRole>(userManager, roleManager, optionsAccessor)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdmtUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        // Add custom claims
        identity.AddClaim(new Claim(IdmtClaimTypes.IsActive, user.IsActive.ToString()));

        // Add tenant claim for multi-tenant strategies (header, claim, route)
        // This ensures token validation includes tenant context
        var claimKey = idmtOptions.Value.MultiTenant.StrategyOptions.GetValueOrDefault(IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);

        // Try to get tenant info from store using user's TenantId
        var tenantInfo = await tenantStore.GetAsync(user.TenantId);
        if (tenantInfo is null)
        {
            logger.LogWarning("Tenant information not found for tenant ID: {TenantId}. User ID: {UserId}. Returning identity without tenant claim.", user.TenantId, user.Id);
            return identity;
        }

        identity.AddClaim(new Claim(claimKey, tenantInfo.Identifier));

        return identity;
    }
}
