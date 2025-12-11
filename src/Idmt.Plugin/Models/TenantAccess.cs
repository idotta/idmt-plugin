namespace Idmt.Plugin.Models;

/// <summary>
/// Entity to track which staff users can access which tenants
/// </summary>
public sealed class TenantAccess : IAuditable
{
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// System user ID (user in "system" tenant)
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Target tenant ID the user can access
    /// </summary>
    public string TenantId { get; set; } = null!;

    /// <summary>
    /// Whether access is currently active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Optional expiration date
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    public string GetId() => Id.ToString();

    public string GetName() => nameof(TenantAccess);

    public string? GetTenantId() => TenantId;
}