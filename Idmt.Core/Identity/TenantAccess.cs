namespace Idmt.Core.Identity;

/// <summary>
/// The user-to-tenant edge: the pair (<see cref="UserId"/>, <see cref="TenantId"/>)
/// with an active flag and an optional UTC expiry. This is the gate. No user, not
/// even a system administrator, gets a token for a tenant without an active,
/// unexpired row.
/// </summary>
/// <remarks>
/// Deliberately NOT multi-tenant: the issuance gate queries it by
/// (userId, tenantId) at the token endpoint, where no ambient tenant exists to
/// filter on. <see cref="TenantId"/> stores the Finbuckle tenant IDENTIFIER
/// string, not the Finbuckle internal Id, so the gate query is a direct equality
/// match keyed on the value the issuance pipeline resolves.
/// </remarks>
public sealed class TenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid UserId { get; set; }
    public required string TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}
