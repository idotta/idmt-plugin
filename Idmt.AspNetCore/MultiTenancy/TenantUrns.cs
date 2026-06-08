namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// The per-tenant audience URN, which is also the RFC 8707 <c>resource</c> value.
/// A single helper owns both directions of the conversion so issuance, the seeder,
/// and the per-request validation handler never disagree about the string format.
/// Never hand-build the URN: a single divergent format on one path defeats the
/// audience binding on every request that takes it.
/// </summary>
public static class TenantUrns
{
    /// <summary>The fixed audience prefix, for example <c>urn:idmt:tenant:acme</c>.</summary>
    public const string Prefix = "urn:idmt:tenant:";

    /// <summary>Builds the audience URN from a tenant identifier.</summary>
    public static string For(string identifier) => Prefix + identifier;

    /// <summary>
    /// Parses the identifier back out of a URN, returning <see langword="null"/> when
    /// the string does not carry the prefix, so a malformed or unrelated audience
    /// value never silently parses as a tenant.
    /// </summary>
    public static string? IdentifierFrom(string urn) =>
        urn.StartsWith(Prefix, StringComparison.Ordinal) ? urn[Prefix.Length..] : null;
}
