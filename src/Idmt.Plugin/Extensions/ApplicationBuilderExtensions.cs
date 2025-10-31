using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;

namespace Idmt.Plugin.Extensions;

/// <summary>
/// Extension methods for configuring IDMT application pipeline
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds IDMT middleware to the application pipeline
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder UseIdmt(this IApplicationBuilder app)
    {
        // Add multi-tenant middleware - must come before authentication
        app.UseMultiTenant();

        // Add authentication and authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Add current user middleware after authentication
        app.UseMiddleware<CurrentUserMiddleware>();

        return app;
    }

    /// <summary>
    /// Ensures the database is created and optionally migrated.
    /// Only IdmtDbContext is used for migrations since it owns all table configurations.
    /// IdmtTenantStoreDbContext shares the same database but doesn't manage schema.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="autoMigrate">Whether to automatically run migrations</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder EnsureIdmtDatabase(this IApplicationBuilder app, bool autoMigrate = false)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var services = scope.ServiceProvider;

        var options = services.GetRequiredService<IOptions<IdmtOptions>>();
        var context = services.GetRequiredService<IdmtDbContext>();

        try
        {
            var shouldMigrate = autoMigrate || options.Value.Database.AutoMigrate;

            if (shouldMigrate)
            {
                // Try to migrate, fall back to EnsureCreated if migrations not supported
                try
                {
                    context.Database.Migrate();
                }
                catch (InvalidOperationException)
                {
                    // Migrations not supported (e.g., in-memory database)
                    context.Database.EnsureCreated();
                }
            }
            else
            {
                context.Database.EnsureCreated();
            }

            // NOTE: IdmtTenantStoreDbContext shares the same database/connection
            // No separate initialization needed - it accesses tables created above
        }
        catch (Exception ex)
        {
            // Log the error - in a real implementation you'd use ILogger
            Console.WriteLine($"Database initialization failed: {ex.Message}");
            throw;
        }

        return app;
    }

    /// <summary>
    /// Seeds initial data for multi-tenant setup
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="seedAction">Optional custom seed action</param>
    /// <returns>The application builder</returns>
    public static async Task<IApplicationBuilder> SeedIdmtDataAsync(this IApplicationBuilder app, Func<IServiceProvider, Task>? seedAction = null)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var services = scope.ServiceProvider;
        try
        {
            // Run default seeding
            await SeedDefaultDataAsync(services);

            // Run custom seeding if provided
            if (seedAction != null)
            {
                await seedAction(services);
            }
        }
        catch (Exception ex)
        {
            // Log the error - in a real implementation you'd use ILogger
            Console.WriteLine($"Data seeding failed: {ex.Message}");
        }

        return app;
    }

    private static async Task SeedDefaultDataAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<IdmtOptions>>();

        // Seed default tenant if using multi-tenant store
        var tenantStore = services.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var defaultTenantId = options.Value.MultiTenant.DefaultTenantId;
        var existingTenant = await tenantStore.TryGetAsync(defaultTenantId);

        if (existingTenant == null)
        {
            var defaultTenant = new IdmtTenantInfo
            {
                Id = defaultTenantId,
                Identifier = defaultTenantId,
                Name = "System Tenant",
                DisplayName = "System",
                IsActive = true
            };

            await tenantStore.TryAddAsync(defaultTenant);
        }
    }
}