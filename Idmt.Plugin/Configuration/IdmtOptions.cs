namespace Idmt.Plugin.Configuration;

/// <summary>
/// Configuration options for the IDMT plugin
/// </summary>
public class IdmtOptions
{
    /// <summary>
    /// Gets the default IDMT configuration
    /// </summary>
    public static IdmtOptions Default => new()
    {
        MultiTenant = new MultiTenantOptions
        {
            Strategies = [IdmtMultiTenantStrategy.Header, IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.Route]
        }
    };

    /// <summary>
    /// Application configuration options
    /// </summary>
    public ApplicationOptions Application { get; set; } = new();

    /// <summary>
    /// Identity configuration options
    /// </summary>
    public IdmtAuthOptions Identity { get; set; } = new();

    /// <summary>
    /// Multi-tenant configuration options
    /// </summary>
    public MultiTenantOptions MultiTenant { get; set; } = new();

    /// <summary>
    /// Database configuration options
    /// </summary>
    public DatabaseOptions Database { get; set; } = new();

    /// <summary>
    /// Rate limiting configuration options for auth endpoints
    /// </summary>
    public RateLimitingOptions RateLimiting { get; set; } = new();

}

/// <summary>
/// Controls how email confirmation links behave.
/// </summary>
public enum EmailConfirmationMode
{
    /// <summary>
    /// Email link points to GET /auth/confirm-email on the server, which confirms
    /// the email directly (like Microsoft's reference implementation).
    /// No client-side form needed for email confirmation.
    /// </summary>
    ServerConfirm,

    /// <summary>
    /// Email link points to ClientUrl/ConfirmEmailFormPath on the client app.
    /// The client reads the token from the URL and calls POST /auth/confirm-email.
    /// Default for SPA/mobile apps.
    /// </summary>
    ClientForm
}

/// <summary>
/// Application configuration options
/// </summary>
public class ApplicationOptions
{
    /// <summary>
    /// URI prefix applied to all IDMT endpoint groups (/auth, /manage, /admin, /health).
    /// Defaults to "/api/v1". Set to "" to restore the legacy unprefixed behavior.
    /// Examples: "/api/v1", "/v2", "/api/v2", ""
    /// </summary>
    public string ApiPrefix { get; set; } = "/api/v1";

    /// <summary>
    /// Base URL of the client application, if any (e.g. "https://myapp.com")
    /// </summary>
    public string? ClientUrl { get; set; }

    /// <summary>
    /// Prefix for WebSocket/SignalR connections
    /// </summary>
    public string WebSocketPrefix { get; set; } = "/hubs";

    public string ResetPasswordFormPath { get; set; } = "/reset-password";
    public string ConfirmEmailFormPath { get; set; } = "/confirm-email";

    /// <summary>
    /// Controls how email confirmation links are generated.
    /// ServerConfirm: link hits GET /auth/confirm-email which confirms directly.
    /// ClientForm: link points to ClientUrl/ConfirmEmailFormPath for SPA handling.
    /// </summary>
    public EmailConfirmationMode EmailConfirmationMode { get; set; } = EmailConfirmationMode.ClientForm;
}

/// <summary>
/// ASP.NET Core Identity configuration
/// </summary>
public class IdmtAuthOptions
{
    public const string CookieOrBearerScheme = "CookieOrBearer";

    public const string CookieOnlyPolicy = "CookieOnly";
    public const string BearerOnlyPolicy = "BearerOnly";
    public const string RequireSysAdminPolicy = "RequireSysAdmin";
    public const string RequireSysUserPolicy = "RequireSysUser";
    public const string RequireTenantManagerPolicy = "RequireTenantManager";

    /// <summary>
    /// Password requirements
    /// </summary>
    public IdmtPasswordOptions Password { get; set; } = new();

    /// <summary>
    /// User requirements
    /// </summary>
    public UserOptions User { get; set; } = new();

    /// <summary>
    /// Sign-in requirements
    /// </summary>
    public SignInOptions SignIn { get; set; } = new();

    /// <summary>
    /// Cookie configuration options
    /// </summary>
    public IdmtCookieOptions Cookie { get; set; } = new();

    /// <summary>
    /// Bearer token configuration options
    /// </summary>
    public BearerOptions Bearer { get; set; } = new();

    /// <summary>
    /// Role configuration options
    /// </summary>
    public string[] ExtraRoles { get; set; } = [];
}

/// <summary>
/// Password configuration options
/// </summary>
public class IdmtPasswordOptions
{
    public bool RequireDigit { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; } = false;
    public int RequiredLength { get; set; } = 8;
    public int RequiredUniqueChars { get; set; } = 1;
}

/// <summary>
/// User configuration options
/// </summary>
public class UserOptions
{
    public bool RequireUniqueEmail { get; set; } = true;
    public string AllowedUserNameCharacters { get; set; } = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
}

/// <summary>
/// Sign-in configuration options
/// </summary>
public class SignInOptions
{
    public bool RequireConfirmedEmail { get; set; } = true;
    public bool RequireConfirmedPhoneNumber { get; set; } = false;
}

/// <summary>
/// Cookie configuration options
/// </summary>
public class IdmtCookieOptions
{
    public string Name { get; set; } = ".Idmt.Application";
    public bool HttpOnly { get; set; } = true;
    public Microsoft.AspNetCore.Http.CookieSecurePolicy SecurePolicy { get; set; } = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;

    /// <summary>
    /// Controls the SameSite attribute of the authentication cookie.
    /// Defaults to <see cref="Microsoft.AspNetCore.Http.SameSiteMode.Strict"/>, which means the
    /// browser will never send the cookie on cross-site requests (neither top-level navigations
    /// nor sub-resource loads). This is the strongest available CSRF protection at the cookie
    /// layer and removes the need for anti-forgery tokens on state-mutating endpoints that rely
    /// solely on cookie authentication.
    ///
    /// Change to <see cref="Microsoft.AspNetCore.Http.SameSiteMode.Lax"/> only if your
    /// application requires cookie preservation on top-level cross-site GET navigations (e.g.
    /// OAuth / OIDC redirect flows), and compensate with explicit anti-forgery validation on
    /// every state-mutating endpoint.
    /// </summary>
    public Microsoft.AspNetCore.Http.SameSiteMode SameSite { get; set; } = Microsoft.AspNetCore.Http.SameSiteMode.Strict;

    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromDays(14);
    public bool SlidingExpiration { get; set; } = true;
    public bool IsRedirectEnabled { get; set; } = false;
    public string LoginPath { get; set; } = "/login";
    public string LogoutPath { get; set; } = "/logout";
    public string AccessDeniedPath { get; set; } = "/access-denied";
}

public class BearerOptions
{
    public const string HeaderTokenPrefix = "Bearer";

    /// <summary>
    /// For SignalR/WebSocket connections, the token is passed as a query parameter
    /// </summary>
    public const string QueryTokenPrefix = "access_token";

    public TimeSpan BearerTokenExpiration { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenExpiration { get; set; } = TimeSpan.FromDays(30);
}


public static class IdmtMultiTenantStrategy
{
    // Strategy names

    public const string Header = "header";
    public const string Claim = "claim";
    public const string Route = "route";
    public const string BasePath = "basepath";

    // Strategy options defaults

    public const string DefaultHeader = "__tenant__";
    public const string DefaultClaim = "tenant";
    public const string DefaultRouteParameter = "__tenant__";
}

/// <summary>
/// Multi-tenant configuration options
/// </summary>
public class MultiTenantOptions
{
    /// <summary>
    /// Default tenant Identifier
    /// </summary>
    public const string DefaultTenantIdentifier = "system-tenant";

    public string DefaultTenantName { get; set; } = "System Tenant";

    /// <summary>
    /// Tenant resolution strategy (header, subdomain, etc.)
    /// </summary>
    public string[] Strategies { get; set; } = [];

    /// <summary>
    /// Strategy-specific configuration
    /// </summary>
    public Dictionary<string, string> StrategyOptions { get; set; } = [];
}

/// <summary>
/// Controls how the IDMT database schema is initialized on startup.
/// </summary>
public enum DatabaseInitializationMode
{
    /// <summary>
    /// Use EF Core Migrations. Consumers must create and apply migrations themselves.
    /// Recommended for production. Default.
    /// </summary>
    Migrate,

    /// <summary>
    /// Use EnsureCreated for quick setup. Not compatible with migrations.
    /// Suitable for development, testing, and prototyping only.
    /// </summary>
    EnsureCreated,

    /// <summary>
    /// Skip automatic database initialization. Consumer manages the database schema externally.
    /// </summary>
    None
}

/// <summary>
/// Database configuration options
/// </summary>
public class DatabaseOptions
{
    /// <summary>
    /// Controls how the database schema is initialized on startup.
    /// <see cref="DatabaseInitializationMode.Migrate"/> runs EF Core migrations and is the
    /// default for production use. <see cref="DatabaseInitializationMode.EnsureCreated"/> is
    /// suitable for development, testing, and prototyping where migrations are not used.
    /// <see cref="DatabaseInitializationMode.None"/> skips initialization entirely and leaves
    /// schema management to the consumer.
    /// </summary>
    public DatabaseInitializationMode DatabaseInitialization { get; set; } = DatabaseInitializationMode.Migrate;
}

/// <summary>
/// Rate limiting configuration for IDMT auth endpoints.
/// When enabled, a fixed-window limiter named "idmt-auth" is registered and applied
/// to all authentication endpoints (login, token, forgot-password, etc.) to protect
/// against brute-force and email-flooding attacks.
/// </summary>
public class RateLimitingOptions
{
    /// <summary>
    /// Enable built-in rate limiting for auth endpoints. Default: false.
    /// Opt-in for production deployments to protect against brute-force and email-flooding attacks.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Maximum number of requests allowed per window for auth endpoints. Default: 10.
    /// </summary>
    public int PermitLimit { get; set; } = 10;

    /// <summary>
    /// Duration of the fixed window in seconds. Default: 60.
    /// </summary>
    public int WindowInSeconds { get; set; } = 60;
}