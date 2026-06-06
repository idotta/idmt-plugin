namespace Idmt.Core.Ports;

/// <summary>
/// The client gate for pure client-credentials grants (no user subject). Mirrors
/// <see cref="ITenantAccessGate"/> but keys on the OAuth <c>client_id</c> instead
/// of a user id, reading ClientTenantAccess with the same active-and-unexpired
/// predicate.
/// </summary>
/// <remarks>
/// <paramref name="clientId"/> is the OAuth client_id; <paramref name="tenantIdentifier"/>
/// is the Finbuckle identifier string.
/// </remarks>
public interface IClientTenantAccessGate
{
    Task<bool> CanAccessAsync(string clientId, string tenantIdentifier, CancellationToken ct);
}
