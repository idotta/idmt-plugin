using Microsoft.AspNetCore.Identity;

namespace Idmt.Core.Identity;

/// <summary>
/// The canonical, global identity for a human. One row per human across all
/// tenants regardless of how many tenants that human can reach;
/// <see cref="IdentityUser{TKey}.NormalizedEmail"/> is globally unique and there
/// is no <c>TenantId</c>. Carried forward unchanged from the shipped 2.0.0 model
/// (ADR-0001).
/// </summary>
public class IdmtUser : IdentityUser<Guid>
{
    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public override string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();

    /// <summary>Global system-role capability, projected as a role claim at sign-in.</summary>
    public SysRoleKind SysRole { get; set; } = SysRoleKind.None;

    /// <summary>Staging slot for the out-of-band email-change flow; null when no change is pending.</summary>
    public string? PendingEmail { get; set; }

    /// <summary>Soft-delete flag.</summary>
    public bool IsActive { get; set; } = true;

    public DateTimeOffset? LastLoginAt { get; set; }
}
