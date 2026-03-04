using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Extensions;

public delegate Task SeedDataAsync(IServiceProvider services);

/// <summary>
/// Extension methods for configuring IDMT application pipeline
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds IDMT middleware to the application pipeline, including security headers.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder UseIdmt(this IApplicationBuilder app)
    {
        // Security headers
        app.Use(async (context, next) =>
        {
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers.XFrameOptions = "DENY";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            context.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
            await next();
        });

        // Add multi-tenant middleware - must come before authentication
        app.UseMultiTenant();

        // Add authentication and authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Add current user middleware after authentication
        app.UseMiddleware<ValidateBearerTokenTenantMiddleware>();
        app.UseMiddleware<CurrentUserMiddleware>();

        // Verify that the user store supports email operations (required for Idmt.Plugin)
        VerifyUserStoreSupportsEmail(app);

        return app;
    }

    /// <summary>
    /// Maps the IDMT endpoints. In case of route or basepath strategy, it's up
    /// to the caller to pass an adequate endpoint route builder.
    /// For example, if using the route strategy, the caller should pass the
    /// endpoint route builder for the tenant, e.g. `/{__tenant__?}`.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>The endpoint route builder</returns>
    public static IEndpointRouteBuilder MapIdmtEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapAuthEndpoints();
        endpoints.MapAuthManageEndpoints();
        endpoints.MapAdminEndpoints();
        endpoints.MapHealthChecks("/healthz").RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy);
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
    public static async Task EnsureIdmtDatabaseAsync(this IApplicationBuilder app, bool autoMigrate = false)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var services = scope.ServiceProvider;

        var options = services.GetRequiredService<IOptions<IdmtOptions>>();
        var context = services.GetRequiredService<IdmtDbContext>();

        var shouldMigrate = autoMigrate || options.Value.Database.AutoMigrate;

        if (shouldMigrate)
        {
            // Try to migrate, fall back to EnsureCreated if migrations not supported
            try
            {
                await context.Database.MigrateAsync();
            }
            catch (InvalidOperationException)
            {
                // Migrations not supported (e.g., in-memory database)
                await context.Database.EnsureCreatedAsync();
            }
        }
        else
        {
            await context.Database.EnsureCreatedAsync();
        }

        // NOTE: IdmtTenantStoreDbContext shares the same database/connection
        // No separate initialization needed - it accesses tables created above
    }

    /// <summary>
    /// Seeds initial data for multi-tenant setup
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="seedAction">Optional custom seed action</param>
    /// <returns>The application builder</returns>
    public static async Task<IApplicationBuilder> SeedIdmtDataAsync(this IApplicationBuilder app, SeedDataAsync? seedAction = null)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var services = scope.ServiceProvider;
        // Run default seeding
        await SeedDefaultDataAsync(services);

        // Run custom seeding if provided
        if (seedAction != null)
        {
            await seedAction(services);
        }

        return app;
    }

    private static async Task SeedDefaultDataAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<IdmtOptions>>();
        var createTenantHandler = services.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        await createTenantHandler.HandleAsync(new CreateTenant.CreateTenantRequest(
            MultiTenantOptions.DefaultTenantIdentifier,
            options.Value.MultiTenant.DefaultTenantName));
    }

    private static void VerifyUserStoreSupportsEmail(IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var userStore = scope.ServiceProvider.GetService<IUserStore<IdmtUser>>();
        if (userStore is null)
        {
            throw new InvalidOperationException("No IUserStore<IdmtUser> is registered. Ensure Identity is configured before calling UseIdmt().");
        }
        if (userStore is not IUserEmailStore<IdmtUser>)
        {
            throw new NotSupportedException("Idmt.Plugin requires a user store that supports email (IUserEmailStore<IdmtUser>).");
        }
    }
}