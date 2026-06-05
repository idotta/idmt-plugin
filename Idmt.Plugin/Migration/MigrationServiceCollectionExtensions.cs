using Idmt.Plugin.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Idmt.Plugin.Migration;

/// <summary>
/// Public DI helpers for the canonical identity migration harness.
/// </summary>
public static class MigrationServiceCollectionExtensions
{
    /// <summary>
    /// Wires the migration tooling into the supplied service collection. Replaces the live
    /// scoped <see cref="ICurrentUserService"/> registration (which expects an HTTP context)
    /// with the migration stub <see cref="MigrationCurrentUserService"/> so audit emission
    /// during <c>SaveChangesAsync</c> does not throw.
    /// </summary>
    /// <remarks>
    /// Call this <b>after</b> <c>AddIdmt&lt;TDbContext&gt;()</c>. The CLI host
    /// <c>Idmt.Migrator</c> is the primary consumer; library users running offline migrations
    /// from custom hosts may also use it.
    /// </remarks>
    public static IServiceCollection AddIdmtMigration(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.RemoveAll<ICurrentUserService>();
        services.AddScoped<ICurrentUserService, MigrationCurrentUserService>();

        services.AddSingleton<CanonicalIdentityDataMigrator>();

        return services;
    }
}
