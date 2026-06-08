using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Finbuckle.MultiTenant.Extensions;
using Idmt.AspNetCore.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Validation;

namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// Wires Finbuckle multi-tenancy onto <see cref="IdmtTenantInfo"/>: the EF Core tenant
/// store and the request-resolution strategies. This is pure Finbuckle wiring; the
/// OpenIddict audience handler is registered separately in
/// <c>AddIdmtOpenIddictServer</c> so the two layers compose independently.
/// </summary>
public static class MultiTenancyServiceCollectionExtensions
{
    /// <summary>
    /// Register <c>AddMultiTenant&lt;IdmtTenantInfo&gt;()</c> with the EF Core store and
    /// the configured resolution strategies. The returned builder lets the caller layer
    /// further Finbuckle configuration (for example per-tenant authentication).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional strategy configuration; defaults to header + route.</param>
    public static MultiTenantBuilder<IdmtTenantInfo> AddIdmtMultiTenancy(
        this IServiceCollection services,
        Action<IdmtTenantResolutionOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new IdmtTenantResolutionOptions();
        configure?.Invoke(options);

        // Fail fast: with no resolution strategy enabled every request resolves to no tenant
        // and every resource call would 401. A misconfiguration here silently disables the
        // audience binding, so reject it at startup rather than at runtime. Note: a static or
        // default-tenant fallback strategy layered on the returned builder would resolve every
        // request to one tenant and defeat the binding; do not add one.
        if (!options.UseHeaderStrategy && !options.UseRouteStrategy)
        {
            throw new InvalidOperationException(
                "IDMT multi-tenancy requires at least one tenant-resolution strategy to be enabled.");
        }

        // Finbuckle strategies and downstream code resolve the current request context.
        services.AddHttpContextAccessor();

        // The route strategy decorates LinkGenerator, so routing must be registered first.
        services.AddRouting();

        var builder = services.AddMultiTenant<IdmtTenantInfo>()
            .WithEFCoreStore<IdmtTenantStoreDbContext, IdmtTenantInfo>();

        // Strategy precedence follows registration order: header is checked before route.
        if (options.UseHeaderStrategy)
        {
            builder.WithHeaderStrategy(options.HeaderName);
        }

        if (options.UseRouteStrategy)
        {
            builder.WithRouteStrategy(options.RouteParameter, useTenantAmbientRouteValue: true);
        }

        // Locked invariant (ADR §2.6, §2.9): the IDMT-owned per-request audience handler
        // binds a token to the Finbuckle-resolved tenant. It lives here because it depends
        // on the tenant accessor this method registers; multi-tenancy is mandatory in v2,
        // so registering it here keeps it unconditional and non-subtractable.
        services.AddScoped<TenantAudienceValidationHandler>();
        services.AddOpenIddict()
            .AddValidation(o => o.AddEventHandler(TenantAudienceValidationHandler.Descriptor));

        // Startup self-check (ADR §2.9): keep tenant URNs out of the static OpenIddict
        // resource set, so the engine's own ValidateResources keeps rejecting any stray
        // tenant resource parameter and the refresh audience precedence rule holds.
        services.AddTransient<IStartupFilter, TenantResourceRegistrationGuard>();

        return builder;
    }
}
