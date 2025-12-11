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
    /// The tenant this user belongs to.
    /// </summary>
    public string TenantId { get; set; } = null!;

    /// <summary>
    /// Soft delete flag - inactive users are considered deleted.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// When this user last logged in.
    /// </summary>
    public DateTime? LastLoginAt { get; set; }

    public string GetId() => Id.ToString();

    public string GetName() => nameof(IdmtUser);

    public string? GetTenantId() => TenantId;
}