using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Logout;
using Idmt.Plugin.Features.Register;
using Idmt.Plugin.Features.Login;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Extensions;

/// <summary>
/// Extension methods for configuring IDMT services
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIdmt(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null)
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

        if (configureDb != null)
        {
            services.AddDbContext<IdmtDbContext>(configureDb);
            services.AddScoped<IdmtDbContext>(provider => provider.GetRequiredService<IdmtDbContext>());
        }

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