using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Finbuckle.MultiTenant.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Plugin.Extensions;

public delegate void CustomizeAuthentication(AuthenticationBuilder authenticationBuilder);
public delegate void CustomizeAuthorization(AuthorizationBuilder authorizationBuilder);

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
        Action<IdmtOptions>? configureOptions = null,
        CustomizeAuthentication? customizeAuthentication = null,
        CustomizeAuthorization? customizeAuthorization = null) where TDbContext : IdmtDbContext
    {
        // 1. Configure and register IDMT Options
        var idmtOptions = ConfigureIdmtOptions(services, configuration, configureOptions);

        // 2. Configure Database Contexts
        ConfigureDatabase<TDbContext>(services, configureDb, idmtOptions);

        // 3. Configure MultiTenant
        // ConfigureMultiTenant(services, idmtOptions);

        // 4. Configure Identity
        ConfigureIdentity(services, idmtOptions);

        // 5. Configure Authentication
        ConfigureAuthentication(services, idmtOptions, customizeAuthentication);

        // 6. Configure Authorization
        ConfigureAuthorization(services, customizeAuthorization);

        ConfigureMultiTenant(services, idmtOptions);

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
        var idmtSection = configuration.GetSection("Idmt");

        // If section doesn't exist and no custom configuration, return defaults
        if (!idmtSection.Exists() && configureOptions == null)
        {
            var defaultOptions = IdmtOptions.Default;
            services.Configure<IdmtOptions>(opts => { });
            return defaultOptions;
        }

        var idmtOptions = new IdmtOptions();
        idmtSection.Bind(idmtOptions);

        // Apply defaults for empty arrays (which means they weren't configured)
        if (idmtOptions.MultiTenant.Strategies.Length == 0)
        {
            idmtOptions.MultiTenant.Strategies = IdmtOptions.Default.MultiTenant.Strategies;
        }

        configureOptions?.Invoke(idmtOptions);

        services.Configure<IdmtOptions>(opts =>
        {
            idmtSection.Bind(opts);

            // Apply defaults for empty arrays (which means they weren't configured)
            if (opts.MultiTenant.Strategies.Length == 0)
            {
                opts.MultiTenant.Strategies = IdmtOptions.Default.MultiTenant.Strategies;
            }

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

        // Register as IdmtDbContext for DI (only when using a derived context).
        // NOTE: When TDbContext == IdmtDbContext, adding this would create a self-referential
        // factory (IdmtDbContext -> GetRequiredService<IdmtDbContext> -> ...) and hang/overflow.
        if (typeof(TDbContext) != typeof(IdmtDbContext))
        {
            services.AddScoped<IdmtDbContext>(provider => provider.GetRequiredService<TDbContext>());
        }

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
                case IdmtMultiTenantStrategy.Header:
                    builder.WithHeaderStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("HeaderName", IdmtMultiTenantStrategy.DefaultHeaderName));
                    break;

                case IdmtMultiTenantStrategy.Route:
                    builder.WithRouteStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("RouteParameter", IdmtMultiTenantStrategy.DefaultRouteParameter),
                        useTenantAmbientRouteValue: true);
                    break;

                case IdmtMultiTenantStrategy.Claim:
                    builder.WithClaimStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault("ClaimType", IdmtMultiTenantStrategy.DefaultClaimType));
                    break;

                case IdmtMultiTenantStrategy.BasePath:
                    builder.WithBasePathStrategy();
                    break;

                default:
                    throw new InvalidOperationException($"Unsupported tenant resolution strategy: {strategy}");
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
    }

    private static void ConfigureAuthentication(
        IServiceCollection services,
        IdmtOptions idmtOptions,
        CustomizeAuthentication? customizeAuthentication)
    {
        // Configure authentication with both cookie and bearer token support
        var authenticationBuilder = services.AddAuthentication(options =>
        {
            options.DefaultScheme = AuthOptions.CookieOrBearerScheme;
            options.DefaultChallengeScheme = AuthOptions.CookieOrBearerScheme;
        });

        // Cookie authentication
        authenticationBuilder.AddIdentityCookies();
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = idmtOptions.Identity.Cookie.Name;
            options.Cookie.HttpOnly = idmtOptions.Identity.Cookie.HttpOnly;
            options.Cookie.SecurePolicy = idmtOptions.Identity.Cookie.SecurePolicy;
            options.Cookie.SameSite = idmtOptions.Identity.Cookie.SameSite;
            options.ExpireTimeSpan = idmtOptions.Identity.Cookie.ExpireTimeSpan;
            options.SlidingExpiration = idmtOptions.Identity.Cookie.SlidingExpiration;

            // Use tenant-specific paths if available (set by middleware)
            options.LoginPath = idmtOptions.Identity.Cookie.LoginPath;
            options.LogoutPath = idmtOptions.Identity.Cookie.LogoutPath;
            options.AccessDeniedPath = idmtOptions.Identity.Cookie.AccessDeniedPath;

            // API-friendly responses (no redirects)
            if (!idmtOptions.Identity.Cookie.IsRedirectEnabled)
            {
                options.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToLogin = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return Task.CompletedTask;
                    },
                    OnRedirectToAccessDenied = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return Task.CompletedTask;
                    }
                };
            }
        });

        // Bearer token authentication
        authenticationBuilder.AddBearerToken(IdentityConstants.BearerScheme, options =>
        {
            options.BearerTokenExpiration = idmtOptions.Identity.Bearer.BearerTokenExpiration;
            options.RefreshTokenExpiration = idmtOptions.Identity.Bearer.RefreshTokenExpiration;

            options.Events = new BearerTokenEvents
            {
                OnMessageReceived = context =>
                {
                    // Support token from query string for SignalR/WebSocket
                    var accessToken = context.Request.Query[BearerOptions.QueryTokenPrefix];
                    var path = context.HttpContext.Request.Path;

                    if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments(idmtOptions.Application.WebSocketPrefix))
                    {
                        context.Token = accessToken;
                    }
                    return Task.CompletedTask;
                }
            };
        });

        // PolicyScheme - automatically routes based on request
        authenticationBuilder.AddPolicyScheme(AuthOptions.CookieOrBearerScheme, "Cookie or Bearer", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                // If Authorization header with Bearer token exists, use bearer scheme
                var authHeader = context.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return IdentityConstants.BearerScheme;
                }

                // Otherwise use cookie scheme (will check for cookie)
                return IdentityConstants.ApplicationScheme;
            };
        });

        customizeAuthentication?.Invoke(authenticationBuilder);
    }

    private static void ConfigureAuthorization(IServiceCollection services, CustomizeAuthorization? customizeAuthorization)
    {
        // Configure authorization
        var authorizationBuilder = services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder(AuthOptions.CookieOrBearerScheme)
            .RequireAuthenticatedUser()
            .Build())

            // Cookie-only policy (rare - for web-specific features)
            .AddPolicy(AuthOptions.CookieOnlyPolicy, policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme))

            // Bearer-only policy (rare - for strict API endpoints)
            .AddPolicy(AuthOptions.BearerOnlyPolicy, policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(IdentityConstants.BearerScheme))

            // Add system admin policy
            .AddPolicy(AuthOptions.RequireSysAdminPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin)
                    .AddAuthenticationSchemes(AuthOptions.CookieOrBearerScheme))

            // Add system user policy
            .AddPolicy(AuthOptions.RequireSysUserPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.SysSupport)
                    .AddAuthenticationSchemes(AuthOptions.CookieOrBearerScheme))

            // Add tenant admin policy
            .AddPolicy(AuthOptions.RequireTenantManagerPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.SysSupport, IdmtDefaultRoleTypes.TenantAdmin)
                    .AddAuthenticationSchemes(AuthOptions.CookieOrBearerScheme));

        customizeAuthorization?.Invoke(authorizationBuilder);
    }

    private static void RegisterApplicationServices(IServiceCollection services)
    {
        // Register scoped services for per-request context
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddScoped<ITenantAccessService, TenantAccessService>();
        services.AddScoped<IIdmtLinkGenerator, IdmtLinkGenerator>();
        services.AddTransient<IEmailSender<IdmtUser>, IdmtEmailSender>();

        // Register HTTP context accessor for service access to HTTP context
        services.AddHttpContextAccessor();
    }

    private static void RegisterFeatures(IServiceCollection services)
    {
        // Auth
        services.AddScoped<Login.ILoginHandler, Login.LoginHandler>();
        services.AddScoped<Login.ITokenLoginHandler, Login.TokenLoginHandler>();
        services.AddScoped<Logout.ILogoutHandler, Logout.LogoutHandler>();
        services.AddScoped<RefreshToken.IRefreshTokenHandler, RefreshToken.RefreshTokenHandler>();
        services.AddScoped<ConfirmEmail.IConfirmEmailHandler, ConfirmEmail.ConfirmEmailHandler>();
        services.AddScoped<ResendConfirmationEmail.IResendConfirmationEmailHandler, ResendConfirmationEmail.ResendConfirmationEmailHandler>();
        services.AddScoped<ForgotPassword.IForgotPasswordHandler, ForgotPassword.ForgotPasswordHandler>();
        services.AddScoped<ResetPassword.IResetPasswordHandler, ResetPassword.ResetPasswordHandler>();

        // Auth/Manage
        services.AddScoped<RegisterUser.IRegisterUserHandler, RegisterUser.RegisterHandler>();
        services.AddScoped<UnregisterUser.IUnregisterUserHandler, UnregisterUser.UnregisterUserHandler>();
        services.AddScoped<UpdateUser.IUpdateUserHandler, UpdateUser.UpdateUserHandler>();
        services.AddScoped<GetUserInfo.IGetUserInfoHandler, GetUserInfo.GetUserInfoHandler>();
        services.AddScoped<UpdateUserInfo.IUpdateUserInfoHandler, UpdateUserInfo.UpdateUserInfoHandler>();

        // Admin
        services.AddScoped<CreateTenant.ICreateTenantHandler, CreateTenant.CreateTenantHandler>();
        services.AddScoped<DeleteTenant.IDeleteTenantHandler, DeleteTenant.DeleteTenantHandler>();
        services.AddScoped<GetUserTenants.IGetUserTenantsHandler, GetUserTenants.GetUserTenantsHandler>();
        services.AddScoped<GrantTenantAccess.IGrantTenantAccessHandler, GrantTenantAccess.GrantTenantAccessHandler>();
        services.AddScoped<RevokeTenantAccess.IRevokeTenantAccessHandler, RevokeTenantAccess.RevokeTenantAccessHandler>();
        services.AddScoped<GetAllTenants.IGetAllTenantsHandler, GetAllTenants.GetAllTenantsHandler>();

        // Health
        services.AddHealthChecks()
            .AddCheck<Features.Health.BasicHealthCheck>("basic");
    }

    private static void RegisterMiddleware(IServiceCollection services)
    {
        // Register middleware as scoped services
        services.AddScoped<CurrentUserMiddleware>();
        services.AddScoped<ValidateBearerTokenTenantMiddleware>();
    }

    #endregion
}