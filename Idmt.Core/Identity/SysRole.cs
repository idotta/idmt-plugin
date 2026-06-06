namespace Idmt.Core.Identity;

/// <summary>
/// Global system-role flag projected as a role claim at sign-in. The string
/// values equal the policy names (see <c>IdmtPolicies</c>) so a SysAdmin user
/// emits a "SysAdmin" role claim that RequireSysAdmin matches without a
/// translation table.
/// </summary>
public enum SysRoleKind
{
    None = 0,
    SysAdmin = 1,
    SysSupport = 2,
}
