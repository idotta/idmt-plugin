using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application user that extends IdentityUser.
/// Username must be at least 3 characters long.
/// </summary>
public class IdmtUser : IdentityUser<Guid>, IAuditable
{
    public override Guid Id { get; set; } = Guid.CreateVersion7();

    public override string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();

    public override string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// System-level role assignment for this user. Defaults to <see cref="SysRoleKind.None"/>.
    /// </summary>
    public SysRoleKind SysRole { get; set; } = SysRoleKind.None;

    /// <summary>
    /// Email address staged for an out-of-band confirmation email change. Null when no change pending.
    /// </summary>
    public string? PendingEmail { get; set; }

    /// <summary>
    /// Soft delete flag - inactive users are considered deleted.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// When this user last logged in.
    /// </summary>
    public DateTimeOffset? LastLoginAt { get; set; }

    public string GetId() => Id.ToString();

    public string GetName() => nameof(IdmtUser);

    /// <summary>
    /// Returns null because <see cref="IdmtUser"/> is a global entity post Phase 1
    /// (canonical identity migration). Audit rows for IdmtUser mutations carry no TenantId.
    /// </summary>
    public string? GetTenantId() => null;
}