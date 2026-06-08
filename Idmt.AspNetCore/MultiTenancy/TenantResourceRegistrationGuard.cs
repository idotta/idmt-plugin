using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// Startup self-check (ADR 0002 §2.9) that pins the invariant the refresh audience
/// precedence rule relies on: tenant URNs must never be registered as static OpenIddict
/// resources (<see cref="OpenIddictServerOptions.Resources"/>). Tenant URNs are scope-store
/// entries; the per-tenant binding rides the granted scope, and the engine's own
/// <c>ValidateResources</c> rejects any stray <c>resource=urn:idmt:tenant:*</c> parameter
/// precisely because it is not a registered resource. If a consumer ever statically
/// registered a tenant URN, that rejection would silently stop and a tenant-A refresh
/// token could mint a tenant-B access token (ADR §2.6). This guard fails fast at startup
/// rather than letting that misconfiguration ship.
/// </summary>
internal sealed class TenantResourceRegistrationGuard(IOptions<OpenIddictServerOptions> options)
    : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        foreach (var resource in options.Value.Resources)
        {
            if (TenantUrns.IdentifierFrom(resource.OriginalString) is not null)
            {
                throw new InvalidOperationException(
                    $"Tenant URN '{resource.OriginalString}' must not be registered as a static OpenIddict " +
                    "resource. Tenant URNs are scope-store entries; registering one as a resource defeats the " +
                    "refresh audience precedence rule (ADR 0002 §2.6).");
            }
        }

        return next;
    }
}
