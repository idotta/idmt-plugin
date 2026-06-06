namespace Idmt.Core.Identity;

/// <summary>
/// The default per-tenant role catalog seeded into every new tenant.
/// </summary>
/// <remarks>
/// SysAdmin/SysSupport are NOT seeded as per-tenant <see cref="IdmtRole"/> rows:
/// system authority is sourced from <see cref="IdmtUser.SysRole"/> plus the
/// uniform TenantAccess gate. The <see cref="SysAdmin"/>/<see cref="SysSupport"/>
/// string constants remain so a policy <c>RequireRole(...)</c> matches against
/// the <see cref="SysRoleKind"/>-emitted role claim.
/// <see cref="Manager"/> is the designated manager role that RequireTenantManager
/// keys on; its per-tenant rows are seeded like the rest of the catalog.
/// </remarks>
public static class IdmtDefaultRoleTypes
{
    public const string SysAdmin = "SysAdmin";
    public const string SysSupport = "SysSupport";
    public const string TenantAdmin = "TenantAdmin"; // The only non-sys role that can create users.
    public const string Manager = "Manager"; // The role RequireTenantManager keys on.

    /// <summary>Default per-tenant roles seeded into every new tenant.</summary>
    public static string[] DefaultRoles =>
    [
        TenantAdmin,
        Manager,
    ];
}
