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
    IMultiTenantContextAccessor multiTenantContextAccessor,
    IOptions<IdmtOptions> idmtOptions,
    ILogger<IdmtUserClaimsPrincipalFactory> logger)
    : UserClaimsPrincipalFactory<IdmtUser, IdmtRole>(userManager, roleManager, optionsAccessor)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdmtUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        // Fail-closed (CD-4): principal generation requires an ambient tenant context.
        // Without it we cannot emit the tenant claim — refuse to issue a principal at all
        // rather than silently dropping the claim.
        var tenantInfo = multiTenantContextAccessor.MultiTenantContext?.TenantInfo;
        if (tenantInfo is null)
        {
            throw new InvalidOperationException(
                "IdmtUserClaimsPrincipalFactory invoked without ambient tenant context. " +
                "Ensure tenant resolver runs in middleware before authentication.");
        }

        // Add IsActive claim
        identity.AddClaim(new Claim(IdmtClaimTypes.IsActive, user.IsActive.ToString()));

        // Tenant claim is sourced from the ambient MultiTenant context (post Phase 1) —
        // user.TenantId no longer exists. The strategy claim type is configurable via IdmtOptions.
        var claimKey = idmtOptions.Value.MultiTenant.StrategyOptions.GetValueOrDefault(
            IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);

        identity.AddClaim(new Claim(claimKey, tenantInfo.Identifier ?? string.Empty));

        // Emit the SysRole claim only when the user has been assigned a system role.
        // Enum string values ("SysAdmin"/"SysSupport") match the existing role-policy strings
        // so RequireSysAdmin/RequireSysUser policies match without per-tenant role membership.
        if (user.SysRole != SysRoleKind.None)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, user.SysRole.ToString()));
        }

        logger.LogDebug(
            "Generated principal for user {UserId} with ambient tenant {TenantIdentifier}.",
            user.Id, tenantInfo.Identifier);

        return identity;
    }
}
