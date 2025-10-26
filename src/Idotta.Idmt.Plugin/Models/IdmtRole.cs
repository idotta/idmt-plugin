using Microsoft.AspNetCore.Identity;

namespace Idotta.Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application role that extends IdentityRole
/// </summary>
public class IdmtRole : IdentityRole
{
    /// <summary>
    /// The tenant identifier this role belongs to
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// Role description
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Indicates if the role is active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Date when the role was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Date when the role was last updated
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}