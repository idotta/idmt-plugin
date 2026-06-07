using Idmt.AspNetCore.Persistence;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;

namespace Idmt.AspNetCore.Server;

/// <summary>
/// Wires the OpenIddict protocol engine into <c>Idmt.AspNetCore</c>: the EF Core
/// store, the token-issuing server, and the co-hosted local validation that enforces
/// per-request revocation. This is the registration ADR 0002 §2.3-§2.5 locks and the
/// spike proved (<c>spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs</c>).
/// </summary>
public static class OpenIddictServerServiceCollectionExtensions
{
    /// <summary>
    /// Wire the OpenIddict server + co-hosted local validation onto the dedicated
    /// tenant-agnostic <see cref="IdmtOpenIddictDbContext"/>. Reference access tokens
    /// with per-request token-entry validation are LOCKED engine choices (ADR §2.3);
    /// the callbacks are additive only. Certificates and any dev-only transport flags
    /// are the consumer's responsibility via <paramref name="configureServer"/> — the
    /// library never ships development certificates.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureServer">
    /// Additive server configuration applied last (for example, signing and encryption
    /// certificates from a key vault). Production must supply real keys and keep HTTPS
    /// required; development and tests may add development certificates here.
    /// </param>
    /// <param name="configureValidation">
    /// Additive validation configuration applied last. Task 05 registers the IDMT
    /// per-request audience handler through this seam.
    /// </param>
    public static IServiceCollection AddIdmtOpenIddictServer(
        this IServiceCollection services,
        Action<OpenIddictServerBuilder>? configureServer = null,
        Action<OpenIddictValidationBuilder>? configureValidation = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOpenIddict()
            .AddCore(o => o.UseEntityFrameworkCore()
                .UseDbContext<IdmtOpenIddictDbContext>())
            .AddServer(o =>
            {
                o.SetTokenEndpointUris(IdmtServerEndpoints.Token);
                o.SetAuthorizationEndpointUris(IdmtServerEndpoints.Authorization);

                o.AllowClientCredentialsFlow();   // machine-to-machine (ADR 0003)
                o.AllowRefreshTokenFlow();         // rotation + reuse detection (audit N5)
                o.AllowAuthorizationCodeFlow();    // interactive login, PKCE (task 09)
                // No resource-owner password grant (OAuth 2.1, ADR §2.5).
                // No public RFC 8693 token-exchange grant: support tokens are minted
                // server-side so the audit write shares the token-store transaction (task 08).

                o.RegisterScopes(IdmtScopes.Api, IdmtScopes.Support);

                // Locked engine choice — reference (opaque) access tokens (ADR §2.3).
                // The wire value is an opaque handle; the claims live server-side. We
                // keep OpenIddict's default access-token encryption ON: with co-hosted
                // local validation it decrypts transparently, and it keeps the stored
                // payload (subject, scopes, tenant audience) unreadable to anyone with
                // only token-table read access. DisableAccessTokenEncryption() is only
                // for third-party resource servers that cannot do JWE (ADR §2.4 makes
                // that impossible here), so it is deliberately NOT called.
                o.UseReferenceAccessTokens();

                o.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()          // IDMT gate handler runs here (task 06)
                    .EnableAuthorizationEndpointPassthrough(); // IDMT login handler runs here (task 09)

                // Certificates and DisableTransportSecurityRequirement (dev/test only)
                // are supplied by the consumer; the library ships none.
                configureServer?.Invoke(o);
            })
            .AddValidation(o =>
            {
                o.UseLocalServer();              // co-hosted: reads the shared token store
                o.EnableTokenEntryValidation();  // per-request revocation — LOCKED (ADR §2.3)
                o.UseAspNetCore();
                // Task 05 registers the IDMT per-request audience handler here.
                configureValidation?.Invoke(o);
            });

        // Bearer-only resource auth (ADR §2.4): the OpenIddict validation scheme is the default.
        services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        services.AddAuthorization();

        return services;
    }
}
