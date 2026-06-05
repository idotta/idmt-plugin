using Idmt.Spike.Host.Auth;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.Spike.Host.Server;

/// <summary>
/// Gate 6 prerequisite: mints user-subject reference tokens grouped under one
/// OpenIddict authorization per (subject, tenant). Grouping — not an audience
/// column — is how the single-tenant revoke is expressed, because a token entry
/// records no audience (the audience lives only in the encrypted payload). The
/// (subject, tenant) authorization carries a tenant marker scope so the hook can
/// find it again at revoke time.
///
/// These tokens are created directly through the token manager, so they exist in
/// the store and are status-checkable, but they are NOT full bearer-validatable
/// reference tokens (no signed/encrypted payload). Gate 6 asserts revocation via
/// <see cref="IOpenIddictTokenManager.GetStatusAsync"/>, not a bearer round-trip.
/// </summary>
public sealed class UserTokenMint(
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    TimeProvider clock)
{
    private const string TenantScopePrefix = "idmt:authz:tenant:";

    private static string TenantScope(string tenant) => TenantScopePrefix + tenant;

    /// <summary>
    /// Finds, or creates, the (subject, tenant) authorization and returns its id.
    /// NOTE: this check-then-create is idempotent only sequentially. Concurrent
    /// mints for the same (subject, tenant) could create duplicate authorizations,
    /// which would make a later single-tenant revoke under-revoke. The spike is
    /// single-threaded so the proof holds; the real implementation needs a
    /// uniqueness guard or an upsert.
    /// </summary>
    public async Task<string> EnsureTenantAuthorizationAsync(string subject, string tenant, CancellationToken ct)
    {
        var existing = await FindTenantAuthorizationIdAsync(subject, tenant, ct);
        if (existing is not null)
        {
            return existing;
        }

        var authorization = await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            Subject = subject,
            Status = Statuses.Valid,
            Type = AuthorizationTypes.Permanent,
            Scopes = { TenantScope(tenant) },
        }, ct);

        return (await authorizations.GetIdAsync(authorization, ct))!;
    }

    /// <summary>Returns the (subject, tenant) authorization id, or null if none exists.</summary>
    public async Task<string?> FindTenantAuthorizationIdAsync(string subject, string tenant, CancellationToken ct)
    {
        var marker = TenantScope(tenant);
        await foreach (var authorization in authorizations.FindBySubjectAsync(subject, ct))
        {
            var scopes = await authorizations.GetScopesAsync(authorization, ct);
            if (scopes.Contains(marker, StringComparer.Ordinal))
            {
                return await authorizations.GetIdAsync(authorization, ct);
            }
        }

        return null;
    }

    /// <summary>
    /// Mints one reference token for the subject, audienced to the tenant and
    /// linked to the (subject, tenant) authorization. Returns the token id.
    /// </summary>
    public async Task<string> MintAsync(string subject, string tenant, CancellationToken ct)
    {
        var authorizationId = await EnsureTenantAuthorizationAsync(subject, tenant, ct);
        var now = clock.GetUtcNow();

        var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
        {
            Subject = subject,
            AuthorizationId = authorizationId,
            Type = TokenTypeHints.AccessToken,
            Status = Statuses.Valid,
            CreationDate = now,
            ExpirationDate = now.AddMinutes(15),
            ReferenceId = Guid.NewGuid().ToString("N"),
        }, ct);

        return (await tokens.GetIdAsync(token, ct))!;
    }
}
