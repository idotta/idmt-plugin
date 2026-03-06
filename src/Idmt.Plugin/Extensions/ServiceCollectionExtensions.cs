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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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

        // 3. Configure Identity
        ConfigureIdentity(services, idmtOptions);

        // 4. Configure Authentication
        ConfigureAuthentication(services, idmtOptions, customizeAuthentication);

        // 5. Configure Authorization
        ConfigureAuthorization(services, customizeAuthorization);

        // 6. Configure MultiTenant
        ConfigureMultiTenant(services, idmtOptions);

        // 7. Register Application Services
        RegisterApplicationServices(services);

        // 8. Register Feature Handlers
        RegisterFeatures(services);

        // 9. Register Middleware
        RegisterMiddleware(services);

        // 10. Configure Rate Limiting (auth endpoints only)
        ConfigureRateLimiting(services, idmtOptions);

        return services;
    }

    /// <summary>
    /// Adds IDMT services using the default IdmtDbContext.
    /// </summary>
    public static IServiceCollection AddIdmt(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null,
        CustomizeAuthentication? customizeAuthentication = null,
        CustomizeAuthorization? customizeAuthorization = null)
    {
        return services.AddIdmt<IdmtDbContext>(configuration, configureDb, configureOptions, customizeAuthentication, customizeAuthorization);
    }

    #region Private Configuration Methods

    private static IdmtOptions ConfigureIdmtOptions(
        IServiceCollection services,
        IConfiguration configuration,
        Action<IdmtOptions>? configureOptions)
    {
        var idmtSection = configuration.GetSection("Idmt");

        // Register the startup validator so misconfigured options surface immediately
        // at application startup rather than on the first resolve of IOptions<IdmtOptions>.
        services.AddSingleton<IValidateOptions<IdmtOptions>, IdmtOptionsValidator>();

        // If section doesn't exist and no custom configuration, return defaults
        if (!idmtSection.Exists() && configureOptions == null)
        {
            var defaultOptions = IdmtOptions.Default;
            services.Configure<IdmtOptions>(opts => { });
            services.AddOptions<IdmtOptions>().ValidateOnStart();
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

        // Ensure validation is triggered eagerly at startup rather than on first resolve.
        services.AddOptions<IdmtOptions>().ValidateOnStart();

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
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault(IdmtMultiTenantStrategy.Header, IdmtMultiTenantStrategy.DefaultHeader));
                    break;

                case IdmtMultiTenantStrategy.Route:
                    builder.WithRouteStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault(IdmtMultiTenantStrategy.Route, IdmtMultiTenantStrategy.DefaultRouteParameter),
                        useTenantAmbientRouteValue: true);
                    break;

                case IdmtMultiTenantStrategy.Claim:
                    builder.WithClaimStrategy(
                        idmtOptions.MultiTenant.StrategyOptions.GetValueOrDefault(IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim));
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


        // Isolate Cookies per Tenant
        builder.Services.ConfigurePerTenant<CookieAuthenticationOptions, IdmtTenantInfo>(
            IdentityConstants.ApplicationScheme, (options, tenantInfo) =>
            {
                var tenantIdentifier = tenantInfo?.Identifier ?? throw new InvalidOperationException("Tenant information is required to configure cookie options.");
                // Prevents Tenant A's tab from overwriting Tenant B's session
                options.Cookie.Name = $"{idmtOptions.Identity.Cookie.Name}.{tenantIdentifier}";
            });
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
        .AddSignInManager()
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
            options.DefaultScheme = IdmtAuthOptions.CookieOrBearerScheme;
            options.DefaultChallengeScheme = IdmtAuthOptions.CookieOrBearerScheme;
        });

        // Cookie authentication
        authenticationBuilder.AddIdentityCookies();
        services.ConfigureApplicationCookie(options =>
        {
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
        authenticationBuilder.AddPolicyScheme(IdmtAuthOptions.CookieOrBearerScheme, "Cookie or Bearer", options =>
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
            .SetDefaultPolicy(new AuthorizationPolicyBuilder(IdmtAuthOptions.CookieOrBearerScheme)
            .RequireAuthenticatedUser()
            .Build())

            // Cookie-only policy (rare - for web-specific features)
            .AddPolicy(IdmtAuthOptions.CookieOnlyPolicy, policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme))

            // Bearer-only policy (rare - for strict API endpoints)
            .AddPolicy(IdmtAuthOptions.BearerOnlyPolicy, policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(IdentityConstants.BearerScheme))

            // Add system admin policy
            .AddPolicy(IdmtAuthOptions.RequireSysAdminPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin)
                    .AddAuthenticationSchemes(IdmtAuthOptions.CookieOrBearerScheme))

            // Add system user policy
            .AddPolicy(IdmtAuthOptions.RequireSysUserPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.SysSupport)
                    .AddAuthenticationSchemes(IdmtAuthOptions.CookieOrBearerScheme))

            // Add tenant admin policy
            .AddPolicy(IdmtAuthOptions.RequireTenantManagerPolicy, policy =>
                policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.SysSupport, IdmtDefaultRoleTypes.TenantAdmin)
                    .AddAuthenticationSchemes(IdmtAuthOptions.CookieOrBearerScheme));

        customizeAuthorization?.Invoke(authorizationBuilder);
    }

    private static void RegisterApplicationServices(IServiceCollection services)
    {
        // Register scoped services for per-request context
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddScoped<ITenantAccessService, TenantAccessService>();
        services.AddScoped<ITenantOperationService, TenantOperationService>();
        services.AddScoped<ITokenRevocationService, TokenRevocationService>();
        services.AddHostedService<TokenRevocationCleanupService>();
        services.AddScoped<IIdmtLinkGenerator, IdmtLinkGenerator>();
        services.AddTransient<IEmailSender<IdmtUser>, IdmtEmailSender>();

        // Register TimeProvider for testable time access
        services.TryAddSingleton(TimeProvider.System);

        // Register FluentValidation validators
        services.AddValidatorsFromAssemblyContaining<IdmtOptions>(ServiceLifetime.Scoped);

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

    private static void ConfigureRateLimiting(IServiceCollection services, IdmtOptions idmtOptions)
    {
        if (!idmtOptions.RateLimiting.Enabled)
        {
            return;
        }

        services.AddRateLimiter(options =>
        {
            options.AddFixedWindowLimiter("idmt-auth", opt =>
            {
                opt.PermitLimit = idmtOptions.RateLimiting.PermitLimit;
                opt.Window = TimeSpan.FromSeconds(idmtOptions.RateLimiting.WindowInSeconds);
                opt.QueueLimit = 0;
            });
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });
    }

    #endregion
}