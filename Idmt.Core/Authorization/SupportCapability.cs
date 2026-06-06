using Idmt.Core.Identity;

namespace Idmt.Core.Authorization;

/// <summary>
/// The pure domain predicate that decides whether a system user may mint a
/// support token for a tenant. Keeping the decision in the domain means one place
/// tests it and no consumer customization can weaken it. The mint mechanism, the
/// RFC 8693 act claim, the TTL ceiling, and the atomic audit row are
/// infrastructure concerns (see 08-support-token-mint.md).
/// </summary>
public static class SupportCapability
{
    /// <summary>
    /// A system user may mint only when both checks pass: an active SysRole
    /// capability, AND the uniform TenantAccess gate for the target tenant. The
    /// capability is necessary but not sufficient: a system role grants the
    /// ability to be granted tenant access, not ambient access to every tenant.
    /// </summary>
    /// <param name="sysRole">The minting user's <see cref="SysRoleKind"/>.</param>
    /// <param name="tenantAccessGranted">
    /// The gate result the caller already computed for (userId, targetTenant) via
    /// <c>ITenantAccessGate.CanAccessAsync</c>. Passed in so this stays pure.
    /// </param>
    public static bool CanMint(SysRoleKind sysRole, bool tenantAccessGranted) =>
        sysRole != SysRoleKind.None && tenantAccessGranted;
}
