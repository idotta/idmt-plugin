namespace Idmt.Plugin.Models;

/// <summary>
/// Audit log entry for tracking important user actions.
/// </summary>
public class IdmtAuditLog
{
    /// <summary>
    /// Unique identifier for this audit entry.
    /// </summary>
    public ulong Id { get; set; }

    /// <summary>
    /// ID of the user who performed the action.
    /// </summary>
    public Guid? UserId { get; set; }

    /// <summary>
    /// The tenant this action was performed in.
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// The action that was performed.
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// The resource or entity that was affected.
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// ID of the resource that was affected.
    /// </summary>
    public string? ResourceId { get; set; }

    /// <summary>
    /// Additional details about the action.
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// IP address of the user who performed the action.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string from the request.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// When this action occurred.
    /// </summary>
    public DateTime Timestamp { get; set; } = DT.UtcNow;

    /// <summary>
    /// Whether this was a successful action.
    /// </summary>
    public bool Success { get; set; } = true;

    /// <summary>
    /// Any error message if the action failed.
    /// </summary>
    public string? ErrorMessage { get; set; }
}
