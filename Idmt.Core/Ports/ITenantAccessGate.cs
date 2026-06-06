namespace Idmt.Core.Ports;

/// <summary>
/// The uniform user TenantAccess gate. Queried at token issuance for every user
/// grant and at every server-side support-token mint, with no reliance on an
/// ambient tenant (the token endpoint has none). Returns whether an active,
/// unexpired TenantAccess row exists for (userId, tenantIdentifier).
/// </summary>
/// <remarks>
/// The domain owns the decision rule and this port; the implementation lives in
/// Idmt.AspNetCore because it reads a DbContext (see 06-tenant-access-gate.md).
/// <paramref name="tenantIdentifier"/> is the Finbuckle identifier string.
/// </remarks>
public interface ITenantAccessGate
{
    Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct);
}
