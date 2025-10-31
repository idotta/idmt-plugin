namespace Idmt.Plugin.Models;

/// <summary>
/// Represents a specific permission granted to a user within a tenant.
/// This provides fine-grained access control beyond roles.
/// </summary>
public sealed class UserPermission
{
    /// <summary>
    /// Unique identifier for this permission grant.
    /// </summary>
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// ID of the user this permission is granted to.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// The tenant this permission applies to (null for system permissions).
    /// </summary>
    public required string TenantId { get; set; }

    /// <summary>
    /// The specific permission being granted.
    /// </summary>
    public string Permission { get; set; } = string.Empty;

    /// <summary>
    /// Optional resource identifier this permission applies to.
    /// </summary>
    public string? ResourceId { get; set; }

    /// <summary>
    /// When this permission was granted.
    /// </summary>
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// ID of the user who granted this permission.
    /// </summary>
    public Guid GrantedBy { get; set; }

    /// <summary>
    /// Whether this permission is currently active.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
