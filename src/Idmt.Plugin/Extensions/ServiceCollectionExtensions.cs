using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Logout;
using Idmt.Plugin.Features.Register;
using Idmt.Plugin.Features.Login;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Models;

namespace Idmt.Plugin.Extensions;

/// <summary>
/// Extension methods for configuring IDMT services
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIdmt<TDbContext>(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null) where TDbContext : IdmtDbContext
    {
        // Configure options
        var idmtOptions = new IdmtOptions();
        configuration.GetSection("Idmt").Bind(idmtOptions);
        configureOptions?.Invoke(idmtOptions);
        services.Configure<IdmtOptions>(opts =>
        {
            configuration.GetSection("Idmt").Bind(opts);
            configureOptions?.Invoke(opts);
        });

        services.AddDbContext<TDbContext>(configureDb);
        services.AddScoped<IdmtDbContext>(provider => provider.GetRequiredService<TDbContext>());

        // Add MultiTenant
        services.AddMultiTenant<IdmtTenantInfo>()
            // TODO: Add strategies
            .WithEFCoreStore<IdmtTenantStoreDbContext, IdmtTenantInfo>()
            .WithPerTenantAuthentication();

        services.RegisterFeatures();

        return services;
    }

    private static void RegisterFeatures(this IServiceCollection services)
    {
        // Register feature handlers
        services.AddScoped<ILoginHandler, LoginHandler>();
        services.AddScoped<IRegisterHandler, RegisterHandler>();
        services.AddScoped<ILogoutHandler, LogoutHandler>();
    }
}