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
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Idmt.Plugin.Features.Auth;
using System.Reflection;

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

        // Verify that the user store supports email operations (required for Idmt.Plugin)
        VerifyUserStoreSupportsEmail(app);

        return app;
    }

    public static IEndpointRouteBuilder MapIdmtEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapAuthEndpoints();
        return endpoints;
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

    private static void VerifyUserStoreSupportsEmail(IApplicationBuilder app)
    {
        // Check if the service is registered without resolving it to avoid circular dependencies
        var serviceProvider = app.ApplicationServices;

        // Fallback: Use reflection to access service descriptors for older .NET versions
        var serviceDescriptors = GetServiceDescriptors(serviceProvider);
        var userStoreDescriptor = serviceDescriptors.FirstOrDefault(sd => sd.ServiceType == typeof(IUserStore<IdmtUser>)) 
            ?? throw new InvalidOperationException("No IUserStore<IdmtUser> is registered. Ensure Identity is configured before calling UseIdmt().");

        // Check if the implementation type implements IUserEmailStore<IdmtUser>
        var implementationType = userStoreDescriptor.ImplementationType;
        if (implementationType == null)
        {
            // If using a factory or instance, we can't verify without resolving
            // EntityFrameworkStores always implements IUserEmailStore, so we assume it's correct
            return;
        }

        // Verify the implementation type implements IUserEmailStore<IdmtUser>
        var emailStoreType = typeof(IUserEmailStore<IdmtUser>);
        if (!emailStoreType.IsAssignableFrom(implementationType))
        {
            throw new NotSupportedException($"Idmt.Plugin requires a user store that implements IUserEmailStore<IdmtUser> (email support). Found: {implementationType.FullName}");
        }
    }

    private static IEnumerable<ServiceDescriptor> GetServiceDescriptors(IServiceProvider serviceProvider)
    {
        // Use reflection to access the internal CallSiteFactory which contains the service descriptors
        // This avoids resolving services and prevents circular dependency issues
        object? callSiteFactory = null;
        
        var field = serviceProvider.GetType().GetField("_serviceProvider", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? serviceProvider.GetType().GetField("_callSiteFactory", BindingFlags.NonPublic | BindingFlags.Instance);
        
        if (field != null)
        {
            callSiteFactory = field.GetValue(serviceProvider);
        }
        else
        {
            var property = serviceProvider.GetType().GetProperty("CallSiteFactory", BindingFlags.NonPublic | BindingFlags.Instance);
            if (property != null)
            {
                callSiteFactory = property.GetValue(serviceProvider);
            }
        }

        if (callSiteFactory == null)
        {
            return Enumerable.Empty<ServiceDescriptor>();
        }

        // Access the descriptors from the call site factory
        var descriptorsProperty = callSiteFactory.GetType().GetProperty("Descriptors", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (descriptorsProperty != null)
        {
            var descriptors = descriptorsProperty.GetValue(callSiteFactory) as IEnumerable<ServiceDescriptor>;
            return descriptors ?? Enumerable.Empty<ServiceDescriptor>();
        }

        var descriptorsField = callSiteFactory.GetType().GetField("_descriptors", BindingFlags.NonPublic | BindingFlags.Instance);
        if (descriptorsField != null)
        {
            var descriptors = descriptorsField.GetValue(callSiteFactory) as IEnumerable<ServiceDescriptor>;
            return descriptors ?? Enumerable.Empty<ServiceDescriptor>();
        }

        return Enumerable.Empty<ServiceDescriptor>();
    }
}