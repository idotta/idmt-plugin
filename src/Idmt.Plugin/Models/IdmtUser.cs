using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application user that extends IdentityUser
/// </summary>
public class IdmtUser : IdentityUser<Guid>
{
    public override Guid Id { get; set; } = Guid.CreateVersion7();

    public override string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();

    public override string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// The tenant this user belongs to (null for system users).
    /// </summary>
    public string TenantId { get; set; } = null!;

    /// <summary>
    /// Soft delete flag - inactive users are considered deleted.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// When this user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this user was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this user last logged in.
    /// </summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>
    /// ID of the user who created this user.
    /// </summary>
    public Guid CreatedBy { get; set; } = Guid.Empty;

    /// <summary>
    /// ID of the user who last updated this user.
    /// </summary>
    public Guid UpdatedBy { get; set; } = Guid.Empty;
}