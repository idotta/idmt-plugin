namespace Idmt.Core.Authorization;

/// <summary>
/// The public authorization policy names IDMT owns. Both the endpoint
/// scaffolding in Idmt.AspNetCore and consumer code reference one spelling here.
/// Where a name corresponds to a system role it doubles as the SysRoleKind string
/// value, so the policy matches the projected role claim without a mapping layer.
/// </summary>
public static class IdmtPolicies
{
    // Gating authorization policies. Build() registers each as a policy and a
    // failed check returns 403.

    /// <summary>The caller holds the SysAdmin system role.</summary>
    public const string RequireSysAdmin = "RequireSysAdmin";

    /// <summary>The caller holds any active system role (SysAdmin or SysSupport).</summary>
    public const string RequireSysUser = "RequireSysUser";

    /// <summary>The caller holds the designated manager role for the resolved tenant.</summary>
    public const string RequireTenantManager = "RequireTenantManager";

    /// <summary>The caller holds at least one projected tenant-role claim for the resolved tenant.</summary>
    public const string RequireTenantMember = "RequireTenantMember";

    /// <summary>
    /// Not a gating policy: a name used by the handler-side claims-inspection
    /// helper that detects an impersonating support session (the RFC 8693 act
    /// claim). Build() does NOT register it as an authorization policy.
    /// </summary>
    public const string SupportSession = "SupportSession";
}
