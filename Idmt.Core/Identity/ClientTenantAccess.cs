namespace Idmt.Core.Identity;

/// <summary>
/// The client-to-tenant edge, mirroring <see cref="TenantAccess"/> for machine
/// clients. A pure client-credentials grant has no user subject, so the user gate
/// cannot decide it; this is the gate for that path. No client gets a token for a
/// tenant without an active, unexpired row.
/// </summary>
/// <remarks>
/// <see cref="ClientId"/> is the OAuth client_id; <see cref="TenantId"/> stores
/// the Finbuckle tenant IDENTIFIER string, the same value as on
/// <see cref="TenantAccess.TenantId"/>.
/// </remarks>
public sealed class ClientTenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public required string ClientId { get; set; }
    public required string TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}
