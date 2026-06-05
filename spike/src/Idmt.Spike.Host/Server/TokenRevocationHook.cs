using OpenIddict.Abstractions;

namespace Idmt.Spike.Host.Server;

/// <summary>
/// Gate 6: the enforcement behind a SecurityStamp change. When a user's
/// credential changes (password, deactivation, compromise), every token they
/// hold must drop; when a single tenant's TenantAccess is revoked, only that
/// tenant's tokens drop.
///
/// OpenIddict 7.5.0 exposes both as single store calls — <see cref="RevokeAllForUserAsync"/>
/// uses <c>RevokeBySubjectAsync</c> and <see cref="RevokeForUserTenantAsync"/> uses
/// <c>RevokeByAuthorizationIdAsync</c> against the (subject, tenant) authorization
/// grouping established by <see cref="UserTokenMint"/>. This is cleaner than the
/// enumerate-FindBySubjectAsync-and-TryRevokeAsync loop the ADR currently
/// describes, and it sidesteps mutating a live store enumeration on the shared
/// connection. (Recorded for the ADR §2.7 / §7.0 item-6 close-out.)
/// </summary>
public sealed class TokenRevocationHook(
    IOpenIddictTokenManager tokens,
    UserTokenMint mint)
{
    /// <summary>Drops every token the subject holds, across all tenants. Returns the count revoked.</summary>
    public ValueTask<long> RevokeAllForUserAsync(string subject, CancellationToken ct) =>
        tokens.RevokeBySubjectAsync(subject, ct);

    /// <summary>
    /// Drops only the subject's tokens for one tenant, by revoking the
    /// (subject, tenant) authorization. Returns false if the subject holds no
    /// tokens for that tenant.
    /// </summary>
    public async Task<bool> RevokeForUserTenantAsync(string subject, string tenant, CancellationToken ct)
    {
        var authorizationId = await mint.FindTenantAuthorizationIdAsync(subject, tenant, ct);
        if (authorizationId is null)
        {
            return false;
        }

        await tokens.RevokeByAuthorizationIdAsync(authorizationId, ct);
        return true;
    }
}
