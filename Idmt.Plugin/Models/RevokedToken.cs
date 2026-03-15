namespace Idmt.Plugin.Models;

/// <summary>
/// Tracks revoked refresh token families. Any refresh token issued before
/// RevokedAt for the given UserId+TenantId is considered invalid.
/// </summary>
public sealed class RevokedToken
{
    public string TokenId { get; set; } = null!;
    public DateTimeOffset RevokedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
