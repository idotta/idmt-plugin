using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// Registers the three IDMT persistence contexts. The composition root
/// (10-locked-seam.md) calls this; the Finbuckle <c>WithEFCoreStore</c> binding
/// (05) and the OpenIddict <c>AddCore().UseDbContext</c> binding (04) stay with
/// their owning tasks.
/// </summary>
public static class PersistenceServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="IdmtDbContext"/>, <see cref="IdmtOpenIddictDbContext"/>,
    /// and <see cref="IdmtTenantStoreDbContext"/>. The consumer supplies the
    /// provider; the second argument of <paramref name="configureProvider"/> is the
    /// per-context migration-history table name (see <see cref="IdmtMigrationsHistory"/>),
    /// which the consumer threads into its provider call so each context gets a
    /// distinct history table without this method hard-coding a provider. For
    /// example:
    /// <code>
    /// services.AddIdmtPersistence((options, history) =>
    ///     options.UseSqlite(connectionString, sql => sql.MigrationsHistoryTable(history)));
    /// </code>
    /// </summary>
    public static IServiceCollection AddIdmtPersistence(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder, string> configureProvider)
    {
        ArgumentNullException.ThrowIfNull(configureProvider);

        services.AddDbContext<IdmtDbContext>(options =>
            configureProvider(options, IdmtMigrationsHistory.App));

        services.AddDbContext<IdmtOpenIddictDbContext>(options =>
        {
            configureProvider(options, IdmtMigrationsHistory.OpenIddict);
            options.UseOpenIddict();
        });

        services.AddDbContext<IdmtTenantStoreDbContext>(options =>
            configureProvider(options, IdmtMigrationsHistory.TenantStore));

        return services;
    }
}
