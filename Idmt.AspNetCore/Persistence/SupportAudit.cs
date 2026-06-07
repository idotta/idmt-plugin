namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// Support-impersonation audit row. Owned by <see cref="IdmtOpenIddictDbContext"/>
/// so the audit write shares OpenIddict's store transaction: a support-token
/// insert and its audit row commit or roll back together (gate 2). See
/// 08-support-token-mint.md for the mint flow and the atomicity guarantee that
/// drives this placement.
/// </summary>
public sealed class SupportAudit
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid ActorUserId { get; set; }
    public required string TenantId { get; set; }
    public required string Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
