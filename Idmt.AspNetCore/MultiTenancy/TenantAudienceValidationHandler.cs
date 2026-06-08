using Finbuckle.MultiTenant.Abstractions;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// The IDMT-owned per-request audience handler. Successor to v1's
/// <c>ValidateBearerTokenTenantMiddleware</c>, relocated into the OpenIddict
/// validation pipeline. It binds the presented access token to the
/// Finbuckle-resolved tenant and rejects any token whose audience is not bound to
/// exactly that tenant. OpenIddict's built-in audience validation only compares
/// against a static configured set decided at startup; it has no notion of the
/// per-request resolved tenant, so it cannot tell a tenant-A token from a tenant-B
/// token when both audiences are in the static set. This per-request comparison is
/// the part that is genuinely IDMT's, and it is a locked invariant
/// (ADR 0002 §2.6, §2.9).
/// </summary>
/// <remarks>
/// The handler runs late (after the built-in handlers have populated the principal)
/// and assumes Finbuckle's <c>UseMultiTenant</c> ran before <c>UseAuthentication</c>
/// so the accessor is populated when it executes.
/// </remarks>
public sealed class TenantAudienceValidationHandler(IMultiTenantContextAccessor<IdmtTenantInfo> accessor)
    : IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<TenantAudienceValidationHandler>()
            // Run after every built-in authentication handler has populated the principal.
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Only access tokens are tenant-bound; skip other token types.
        if (context.AccessTokenPrincipal is null || context.IsRejected)
        {
            return ValueTask.CompletedTask;
        }

        // Enforce on resource-API requests only. OpenIddict's own validation endpoints
        // (introspection and the configuration/cryptography fetches) carry a non-Unknown
        // endpoint type and are not reached through a tenant-aware route; the engine's own
        // validation owns those. Keying on the engine's resolved endpoint type, rather than
        // the raw request path, means a consumer route that happens to collide with a
        // protocol path cannot escape enforcement.
        if (context.EndpointType is not OpenIddictValidationEndpointType.Unknown)
        {
            return ValueTask.CompletedTask;
        }

        var resolved = accessor.MultiTenantContext?.TenantInfo?.Identifier;
        if (string.IsNullOrEmpty(resolved))
        {
            // No resolved tenant on a token-bound resource request: refuse rather than guess.
            context.Reject(Errors.InvalidToken, "No tenant was resolved for this request.");
            return ValueTask.CompletedTask;
        }

        // The token must bind to EXACTLY the resolved tenant. A membership check would let a
        // token carrying two tenant URNs pass on both tenants' routes; require the set of
        // tenant-URN audiences to be the single resolved one. Non-tenant audiences are ignored.
        // Single allocation-free pass: GetAudiences returns a struct-enumerable ImmutableArray,
        // and StartsWith avoids the substring IdentifierFrom would allocate per audience.
        var expected = TenantUrns.For(resolved);
        var tenantAudienceCount = 0;
        var boundToResolved = false;

        foreach (var audience in context.AccessTokenPrincipal.GetAudiences())
        {
            if (!audience.StartsWith(TenantUrns.Prefix, StringComparison.Ordinal))
            {
                continue;
            }

            tenantAudienceCount++;
            boundToResolved = string.Equals(audience, expected, StringComparison.Ordinal);
        }

        if (tenantAudienceCount != 1 || !boundToResolved)
        {
            context.Reject(Errors.InvalidToken, "Token audience does not bind to exactly the resolved tenant.");
        }

        return ValueTask.CompletedTask;
    }
}
