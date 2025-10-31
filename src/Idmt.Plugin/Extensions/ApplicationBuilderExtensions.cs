using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Middleware;
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
        // Add multi-tenant middleware
        app.UseMultiTenant();

        // Add custom tenant resolution middleware
        app.UseMiddleware<TenantResolutionMiddleware>();

        // Add authentication and authorization
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }

    /// <summary>
    /// Ensures the database is created and optionally migrated
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
            // For in-memory database, just ensure created
            if (context.Database.IsInMemory())
            {
                context.Database.EnsureCreated();
            }
            else if (autoMigrate || options.Value.Database.AutoMigrate)
            {
                context.Database.Migrate();
            }
            else
            {
                context.Database.EnsureCreated();
            }
        }
        catch (Exception ex)
        {
            // Log the error - in a real implementation you'd use ILogger
            Console.WriteLine($"Database initialization failed: {ex.Message}");
        }

        return app;
    }

    /// <summary>
    /// Seeds initial data for multi-tenant setup
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="seedAction">Optional custom seed action</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder SeedIdmtData(this IApplicationBuilder app, Action<IServiceProvider>? seedAction = null)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var services = scope.ServiceProvider;

        try
        {
            // Run default seeding
            SeedDefaultData(services).GetAwaiter().GetResult();

            // Run custom seeding if provided
            seedAction?.Invoke(services);
        }
        catch (Exception ex)
        {
            // Log the error - in a real implementation you'd use ILogger
            Console.WriteLine($"Data seeding failed: {ex.Message}");
        }

        return app;
    }

    private static async Task SeedDefaultData(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<IdmtOptions>>();
        
        // Seed default tenant if using multi-tenant store
        var tenantStore = services.GetService<IMultiTenantStore<TenantInfo>>();
        if (tenantStore != null)
        {
            var defaultTenantId = options.Value.MultiTenant.DefaultTenantId;
            var existingTenant = await tenantStore.TryGetAsync(defaultTenantId);
            
            if (existingTenant == null)
            {
                var defaultTenant = new TenantInfo
                {
                    Id = defaultTenantId,
                    Identifier = defaultTenantId,
                    Name = "Default Tenant"
                };
                
                await tenantStore.TryAddAsync(defaultTenant);
            }
        }
    }
}