using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application role that extends IdentityRole
/// </summary>
public class IdmtRole : IdentityRole<Guid>
{
    public IdmtRole() : base() { }

    public IdmtRole(string name) : base(name) { }

    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public override string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public virtual string[] RoleTypes => [
        IdmtDefaultRoleTypes.SysAdmin,
        IdmtDefaultRoleTypes.SysSupport,
        IdmtDefaultRoleTypes.TenantAdmin,
        IdmtDefaultRoleTypes.TenantUser
    ];
}

/// <summary>
/// Default role types for the IDMT plugin.
/// </summary>
public static class IdmtDefaultRoleTypes
{
    public const string SysAdmin = "SysAdmin";
    public const string SysSupport = "SysSupport";
    public const string TenantAdmin = "TenantAdmin";
    public const string TenantUser = "TenantUser";
}