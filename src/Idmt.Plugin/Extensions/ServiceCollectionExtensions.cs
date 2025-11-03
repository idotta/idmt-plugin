using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Middleware;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Models;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Auth.Manage;

namespace Idmt.Plugin.Extensions;

/// <summary>
/// Extension methods for configuring IDMT services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds IDMT (Identity MultiTenant) services to the application with custom DbContext.
    /// Configures Identity, MultiTenant, authentication, and all required services.
    /// </summary>
    /// <typeparam name="TDbContext">The custom DbContext type that extends IdmtDbContext</typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The application configuration</param>
    /// <param name="configureDb">Optional action to configure the DbContext</param>
    /// <param name="configureOptions">Optional action to configure IDMT options</param>
    /// <returns>The service collection for method chaining</returns>
    public static IServiceCollection AddIdmt<TDbContext>(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null) where TDbContext : IdmtDbContext
    {
        // 1. Configure and register IDMT Options
        var idmtOptions = ConfigureIdmtOptions(services, configuration, configureOptions);

        // 2. Configure Database Contexts
        ConfigureDatabase<TDbContext>(services, configureDb, idmtOptions);

        // 3. Configure MultiTenant
        ConfigureMultiTenant(services, idmtOptions);

        // 4. Configure Identity
        ConfigureIdentity(services, idmtOptions);

        // 5. Configure Authentication
        ConfigureAuthentication(services, idmtOptions);

        // 6. Register Application Services
        RegisterApplicationServices(services);

        // 7. Register Feature Handlers
        RegisterFeatures(services);

        // 8. Register Middleware
        RegisterMiddleware(services);

        return services;
    }

    /// <summary>
    /// Adds IDMT services using the default IdmtDbContext.
    /// </summary>
    public static IServiceCollection AddIdmt(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null)
    {
        return services.AddIdmt<IdmtDbContext>(configuration, configureDb, configureOptions);
    }

    #region Private Configuration Methods

    private static IdmtOptions ConfigureIdmtOptions(
        IServiceCollection services,
        IConfiguration configuration,
        Action<IdmtOptions>? configureOptions)
    {
        var idmtOptions = new IdmtOptions();
        configuration.GetSection("Idmt").Bind(idmtOptions);
        configureOptions?.Invoke(idmtOptions);

        services.Configure<IdmtOptions>(opts =>
        {
            configuration.GetSection("Idmt").Bind(opts);
            configureOptions?.Invoke(opts);
        });

        return idmtOptions;
    }

    private static void ConfigureDatabase<TDbContext>(
        IServiceCollection services,
        Action<DbContextOptionsBuilder>? configureDb,
        IdmtOptions idmtOptions) where TDbContext : IdmtDbContext
    {
        // Register main application DbContext
        if (configureDb != null)
        {
            services.AddDbContext<TDbContext>(configureDb);
        }
        else
        {
            // If no configuration provided, register without options
            // The consumer app must provide database configuration
            services.AddDbContext<TDbContext>();
        }

        // Register as IdmtDbContext for DI
        services.AddScoped<IdmtDbContext>(provider => provider.GetRequiredService<TDbContext>());

        // Register Tenant Store DbContext
        // The Tenant Store typically shares the same database configuration as the main context
        // but could be configured differently if needed
        if (configureDb != null)
        {
            services.AddDbContext<IdmtTenantStoreDbContext>(configureDb);
        }
        else
        {
            services.AddDbContext<IdmtTenantStoreDbContext>();
        }
    }

    private static void ConfigureMultiTenant(IServiceCollection services, IdmtOptions idmtOptions)
    {
        var builder = services.AddMultiTenant<IdmtTenantInfo>()
            .WithEFCoreStore<IdmtTenantStoreDbContext, IdmtTenantInfo>();

        // Register configured strategies
        foreach (var strategy in idmtOptions.MultiTenant.Strategies)
        {
            switch (strategy.ToLowerInvariant())
            {
                case "header":
                    builder.WithHeaderStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("HeaderName", "__tenant__"));
                    break;

                case "route":
                    builder.WithRouteStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("RouteParameter", "__tenant__"));
                    break;

                case "claim":
                    builder.WithClaimStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("ClaimType", "tenant"));
                    break;

                case "host":
                    builder.WithHostStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("HostTemplate", "__tenant__.*"));
                    break;

                case "basepath":
                    builder.WithBasePathStrategy();
                    break;

                default:
                    throw new InvalidOperationException($"Unknown tenant resolution strategy: {strategy}");
            }
        }

        // Enable per-tenant authentication - critical for proper multi-tenant isolation
        builder.WithPerTenantAuthentication();
    }

    private static void ConfigureIdentity(IServiceCollection services, IdmtOptions idmtOptions)
    {
        // Add Identity with custom options
        services.AddIdentityCore<IdmtUser>(options =>
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

            // Lockout settings (best practices)
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;
        })
        .AddRoles<IdmtRole>()
        .AddEntityFrameworkStores<IdmtDbContext>()
        .AddSignInManager<BetterSignInManager>()
        .AddClaimsPrincipalFactory<IdmtUserClaimsPrincipalFactory>()
        .AddDefaultTokenProviders();

        // Configure application cookie for per-tenant authentication
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = ".Idmt.Application";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromDays(14);
            options.SlidingExpiration = true;

            // Use tenant-specific paths if available (set by middleware)
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.AccessDeniedPath = "/access-denied";
        });
    }

    private static void ConfigureAuthentication(IServiceCollection services, IdmtOptions idmtOptions)
    {
        // Configure authentication with both cookie and bearer token support
        services.AddAuthentication(options =>
        {
            // Default scheme for web applications
            options.DefaultScheme = "CookieOrBearer";
            options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
            options.DefaultAuthenticateScheme = "CookieOrBearer";
            options.DefaultChallengeScheme = "CookieOrBearer";
        })
        .AddPolicyScheme("CookieOrBearer", "CookieOrBearer", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                var auth = context.Request.Headers.Authorization.ToString();
                return !string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ")
                    ? IdentityConstants.BearerScheme
                    : IdentityConstants.ApplicationScheme;
            };
        })
        .AddBearerToken(IdentityConstants.BearerScheme)
        .AddIdentityCookies();

        // Add authorization policies
        services.AddAuthorization(options =>
        {
            // Add default policies
            options.AddPolicy("RequireAuthenticatedUser", policy =>
                policy.RequireAuthenticatedUser());
        });
    }

    private static void RegisterApplicationServices(IServiceCollection services)
    {
        // Register scoped services for per-request context
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddScoped<ITenantAccessService, TenantAccessService>();

        // Register HTTP context accessor for service access to HTTP context
        services.AddHttpContextAccessor();
    }

    private static void RegisterFeatures(IServiceCollection services)
    {
        // Auth
        services.AddScoped<Login.ILoginHandler, Login.LoginHandler>();
        services.AddScoped<Logout.ILogoutHandler, Logout.LogoutHandler>();
        services.AddScoped<RefreshToken.IRefreshTokenHandler, RefreshToken.RefreshTokenHandler>();
        services.AddScoped<ConfirmEmail.IConfirmEmailHandler, ConfirmEmail.ConfirmEmailHandler>();
        services.AddScoped<ResendConfirmationEmail.IResendConfirmationEmailHandler, ResendConfirmationEmail.ResendConfirmationEmailHandler>();
        services.AddScoped<ForgotPassword.IForgotPasswordHandler, ForgotPassword.ForgotPasswordHandler>();
        services.AddScoped<ResetPassword.IResetPasswordHandler, ResetPassword.ResetPasswordHandler>();

        // Auth/Manage
        services.AddScoped<RegisterUser.IRegisterUserHandler, RegisterUser.RegisterHandler>();
    }

    private static void RegisterMiddleware(IServiceCollection services)
    {
        // Register middleware as scoped services
        services.AddScoped<CurrentUserMiddleware>();
    }

    #endregion
}