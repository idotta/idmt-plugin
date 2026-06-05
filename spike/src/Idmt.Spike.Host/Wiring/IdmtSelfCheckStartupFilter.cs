using Idmt.Spike.Host.Auth;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Validation;

namespace Idmt.Spike.Host.Wiring;

/// <summary>Thrown when a locked security invariant was subtracted from the configuration.</summary>
public sealed class IdmtSecurityInvariantException(string message) : InvalidOperationException(message);

/// <summary>
/// Gate 5, layer 2 of the §2.9 seam. The last-wins post-configuration
/// (<see cref="SpikeWiring"/>) is the first line that re-applies locked options;
/// this startup filter is the back-stop that reads the FINAL options snapshot at
/// host start and fails fast if a consumer subtracted a locked property after the
/// lock (e.g. a raw <c>PostConfigure</c> registered after <c>AddIdmtSpike</c>).
///
/// It proves detection of registration-expressed subtraction only; a consumer who
/// mutates options at resolve time (a custom <see cref="IPostConfigureOptions{T}"/>
/// running after this snapshot is read) is out of reach, as the ADR §2.9 caveat
/// already concedes.
/// </summary>
public sealed class IdmtSelfCheckStartupFilter(
    IOptions<OpenIddictServerOptions> server,
    IOptions<OpenIddictValidationOptions> validation) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        var s = server.Value;
        var v = validation.Value;

        if (!s.UseReferenceAccessTokens)
        {
            throw new IdmtSecurityInvariantException(
                "Locked invariant violated: UseReferenceAccessTokens must remain enabled.");
        }

        if (s.DisableTokenStorage)
        {
            throw new IdmtSecurityInvariantException(
                "Locked invariant violated: token storage must not be disabled.");
        }

        if (s.EnableDegradedMode)
        {
            throw new IdmtSecurityInvariantException(
                "Locked invariant violated: degraded mode must not be enabled.");
        }

        if (!v.EnableTokenEntryValidation)
        {
            throw new IdmtSecurityInvariantException(
                "Locked invariant violated: EnableTokenEntryValidation must remain enabled.");
        }

        if (!v.Handlers.Any(d => d.ServiceDescriptor.ServiceType == typeof(TenantAudienceValidationHandler)))
        {
            throw new IdmtSecurityInvariantException(
                "Locked invariant violated: the tenant audience validation handler must remain registered.");
        }

        return next;
    }
}
