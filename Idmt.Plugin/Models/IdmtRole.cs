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
    public string TenantId { get; set; } = null!;
}

/// <summary>
/// Default role types for the IDMT plugin.
/// </summary>
public static class IdmtDefaultRoleTypes
{
    public const string SysAdmin = "SysAdmin";
    public const string SysSupport = "SysSupport";
    public const string TenantAdmin = "TenantAdmin"; // The only non sys role that can create users

    /// <summary>
    /// Default per-tenant roles seeded into every new tenant.
    /// Phase 1: SysAdmin/SysSupport are NO LONGER seeded as per-tenant <see cref="IdmtRole"/> rows.
    /// Sys-level authority is sourced from <see cref="IdmtUser.SysRole"/> + ambient TenantAccess gate.
    /// The <see cref="SysAdmin"/> and <see cref="SysSupport"/> string constants remain for policy
    /// <c>RequireRole(...)</c> matches against the <see cref="SysRoleKind"/>-emitted role claim.
    /// </summary>
    public static string[] DefaultRoles => [
        TenantAdmin
    ];
}