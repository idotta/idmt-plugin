using Microsoft.AspNetCore.Identity;

namespace Idotta.Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application user that extends IdentityUser
/// </summary>
public class IdmtUser : IdentityUser
{
    /// <summary>
    /// The tenant identifier this user belongs to
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// User's first name
    /// </summary>
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name
    /// </summary>
    public string? LastName { get; set; }

    /// <summary>
    /// Indicates if the user is active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Date when the user was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Date when the user was last updated
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}