using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Features.Login;
using Idmt.Plugin.Features.Register;
using Idmt.Plugin.Features.Logout;

namespace Idmt.Plugin.Extensions;

/// <summary>
/// Extension methods for configuring IDMT services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds IDMT identity and multi-tenant services to the service collection
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration</param>
    /// <param name="configureOptions">Optional configuration action</param>
    /// <returns>The service collection</returns>
    public static IServiceCollection AddIdmt(
        this IServiceCollection services,
        IConfiguration configuration,
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

        // Add multi-tenant services
        services.AddMultiTenant<TenantInfo>()
            .WithHeaderStrategy("tenant-id")
            .WithInMemoryStore();

        // Add Entity Framework with multi-tenant support
        services.AddDbContext<IdmtDbContext>((serviceProvider, options) =>
        {
            var tenantInfo = serviceProvider.GetService<IMultiTenantContextAccessor>()?.MultiTenantContext?.TenantInfo;
            
            if (idmtOptions.Database.UseSharedDatabase)
            {
                // Use shared database with tenant isolation
                options.UseInMemoryDatabase("IdmtSharedDb");
            }
            else
            {
                // Use tenant-specific database
                var connectionString = idmtOptions.Database.ConnectionStringTemplate.Replace("{tenant}", tenantInfo?.Id ?? "default");
                options.UseInMemoryDatabase($"IdmtDb_{tenantInfo?.Id ?? "default"}");
            }
        });

        // Configure ASP.NET Core Identity
        services.AddIdentity<IdmtUser, IdmtRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = idmtOptions.Identity.Password.RequireDigit;
            options.Password.RequireLowercase = idmtOptions.Identity.Password.RequireLowercase;
            options.Password.RequireUppercase = idmtOptions.Identity.Password.RequireUppercase;
            options.Password.RequireNonAlphanumeric = idmtOptions.Identity.Password.RequireNonAlphanumeric;
            options.Password.RequiredLength = idmtOptions.Identity.Password.RequiredLength;
            options.Password.RequiredUniqueChars = idmtOptions.Identity.Password.RequiredUniqueChars;

            // User settings
            options.User.RequireUniqueEmail = idmtOptions.Identity.User.RequireUniqueEmail;
            options.User.AllowedUserNameCharacters = idmtOptions.Identity.User.AllowedUserNameCharacters;

            // Sign-in settings
            options.SignIn.RequireConfirmedEmail = idmtOptions.Identity.SignIn.RequireConfirmedEmail;
            options.SignIn.RequireConfirmedPhoneNumber = idmtOptions.Identity.SignIn.RequireConfirmedPhoneNumber;
        })
        .AddEntityFrameworkStores<IdmtDbContext>()
        .AddDefaultTokenProviders();

        // Configure JWT authentication
        if (!string.IsNullOrEmpty(idmtOptions.Jwt.SecretKey))
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = idmtOptions.Jwt.Issuer,
                    ValidAudience = idmtOptions.Jwt.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(idmtOptions.Jwt.SecretKey)),
                    ClockSkew = TimeSpan.Zero
                };
            });
        }

        // Register feature handlers
        services.AddScoped<ILoginHandler, LoginHandler>();
        services.AddScoped<IRegisterHandler, RegisterHandler>();
        services.AddScoped<ILogoutHandler, LogoutHandler>();

        return services;
    }

    /// <summary>
    /// Adds IDMT services with Entity Framework
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration</param>
    /// <param name="configureDb">Database configuration action</param>
    /// <param name="configureOptions">Optional configuration action</param>
    /// <returns>The service collection</returns>
    public static IServiceCollection AddIdmtWithEntityFramework<TContext>(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder> configureDb,
        Action<IdmtOptions>? configureOptions = null)
        where TContext : IdmtDbContext
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

        // Add multi-tenant services
        services.AddMultiTenant<TenantInfo>()
            .WithHeaderStrategy("tenant-id")
            .WithInMemoryStore();

        // Add Entity Framework with custom configuration
        services.AddDbContext<TContext>(configureDb);
        services.AddScoped<IdmtDbContext>(provider => provider.GetRequiredService<TContext>());

        // Configure Identity and other services
        return AddIdentityAndServices<TContext>(services, idmtOptions);
    }

    private static IServiceCollection AddIdentityAndServices<TContext>(IServiceCollection services, IdmtOptions idmtOptions)
        where TContext : IdmtDbContext
    {
        // Configure ASP.NET Core Identity
        services.AddIdentity<IdmtUser, IdmtRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = idmtOptions.Identity.Password.RequireDigit;
            options.Password.RequireLowercase = idmtOptions.Identity.Password.RequireLowercase;
            options.Password.RequireUppercase = idmtOptions.Identity.Password.RequireUppercase;
            options.Password.RequireNonAlphanumeric = idmtOptions.Identity.Password.RequireNonAlphanumeric;
            options.Password.RequiredLength = idmtOptions.Identity.Password.RequiredLength;
            options.Password.RequiredUniqueChars = idmtOptions.Identity.Password.RequiredUniqueChars;

            // User settings
            options.User.RequireUniqueEmail = idmtOptions.Identity.User.RequireUniqueEmail;
            options.User.AllowedUserNameCharacters = idmtOptions.Identity.User.AllowedUserNameCharacters;

            // Sign-in settings
            options.SignIn.RequireConfirmedEmail = idmtOptions.Identity.SignIn.RequireConfirmedEmail;
            options.SignIn.RequireConfirmedPhoneNumber = idmtOptions.Identity.SignIn.RequireConfirmedPhoneNumber;
        })
        .AddEntityFrameworkStores<TContext>()
        .AddDefaultTokenProviders();

        // Configure JWT authentication
        if (!string.IsNullOrEmpty(idmtOptions.Jwt.SecretKey))
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = idmtOptions.Jwt.Issuer,
                    ValidAudience = idmtOptions.Jwt.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(idmtOptions.Jwt.SecretKey)),
                    ClockSkew = TimeSpan.Zero
                };
            });
        }

        // Register feature handlers
        services.AddScoped<ILoginHandler, LoginHandler>();
        services.AddScoped<IRegisterHandler, RegisterHandler>();
        services.AddScoped<ILogoutHandler, LogoutHandler>();

        return services;
    }
}