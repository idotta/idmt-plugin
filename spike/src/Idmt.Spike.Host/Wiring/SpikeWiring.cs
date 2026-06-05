using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Finbuckle.MultiTenant.Extensions;
using Idmt.Spike.Host.Auth;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Spike.Host.Wiring;

/// <summary>Holds the per-context in-memory SQLite connections, kept open for the host lifetime.</summary>
public sealed class SpikeConnections : IDisposable
{
    public SqliteConnection Identity { get; } = Open();
    public SqliteConnection Tenant { get; } = Open();
    public SqliteConnection OpenIddict { get; } = Open();
    public SqliteConnection Store { get; } = Open();

    private static SqliteConnection Open()
    {
        var c = new SqliteConnection("DataSource=:memory:");
        c.Open();
        return c;
    }

    public void Dispose()
    {
        Identity.Dispose();
        Tenant.Dispose();
        OpenIddict.Dispose();
        Store.Dispose();
    }
}

public static class SpikeWiring
{
    /// <summary>
    /// The spike composition root. Wires the four contexts (each on its own
    /// :memory: connection), Finbuckle, Identity, and OpenIddict (server +
    /// local validation with reference tokens + token-entry validation), plus
    /// the IDMT-owned gate and audience handler.
    /// </summary>
    public static IServiceCollection AddIdmtSpike(this IServiceCollection services)
    {
        var conns = new SpikeConnections();
        services.AddSingleton(conns);
        services.AddSingleton(TimeProvider.System);

        services.AddDbContext<IdmtIdentityDbContext>(o => o.UseSqlite(conns.Identity));
        services.AddDbContext<IdmtTenantDbContext>(o => o.UseSqlite(conns.Tenant));
        services.AddDbContext<IdmtOpenIddictDbContext>(o =>
        {
            o.UseSqlite(conns.OpenIddict);
            o.UseOpenIddict();
        });
        services.AddDbContext<IdmtTenantStoreDbContext>(o => o.UseSqlite(conns.Store));

        services.AddMultiTenant<IdmtTenantInfo>()
            .WithEFCoreStore<IdmtTenantStoreDbContext, IdmtTenantInfo>()
            .WithHeaderStrategy("X-Tenant")
            .WithRouteStrategy("tenant", useTenantAmbientRouteValue: true);

        services.AddIdentityCore<IdmtUser>(o => o.User.RequireUniqueEmail = true)
            .AddRoles<IdmtRole>()
            .AddEntityFrameworkStores<IdmtIdentityDbContext>()
            .AddDefaultTokenProviders();

        services.AddScoped<ITenantAccessGate, TenantAccessGate>();

        services.AddOpenIddict()
            .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<IdmtOpenIddictDbContext>())
            .AddServer(o =>
            {
                o.SetTokenEndpointUris("/connect/token");

                o.AllowClientCredentialsFlow();
                o.AllowRefreshTokenFlow();
                // No public token-exchange grant: support tokens are minted
                // server-side via the token manager so the audit write can share
                // the token-store transaction (see SupportTokenService). The
                // wire-level RFC 8693 grant defers token creation past the request
                // handler, which would break that atomicity.

                o.RegisterScopes("api", "support");

                // Reference (opaque) access tokens — the locked engine choice.
                o.UseReferenceAccessTokens();
                o.DisableAccessTokenEncryption();

                o.AddDevelopmentEncryptionCertificate();
                o.AddDevelopmentSigningCertificate();

                o.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .DisableTransportSecurityRequirement(); // spike runs over HTTP
            })
            .AddValidation(o =>
            {
                o.UseLocalServer();
                // Per-request revocation: read the token entry every request.
                o.EnableTokenEntryValidation();
                o.UseAspNetCore();
                // Gate 3: IDMT-owned per-request audience binding.
                o.AddEventHandler(TenantAudienceValidationHandler.Descriptor);
            });

        services.AddScoped<TenantAudienceValidationHandler>();

        services.AddAuthentication(OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        services.AddAuthorization();

        return services;
    }
}
