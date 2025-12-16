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
}

/// <summary>
/// Default role types for the IDMT plugin.
/// </summary>
public static class IdmtDefaultRoleTypes
{
    public const string SysAdmin = "SysAdmin";
    public const string SysSupport = "SysSupport";
    public const string TenantAdmin = "TenantAdmin"; // The only non sys role that can create users

    public static string[] DefaultRoles => [
        SysAdmin,
        SysSupport,
        TenantAdmin
    ];
}