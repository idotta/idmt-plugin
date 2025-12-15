using Idmt.Plugin.Models;

namespace Idmt.Plugin.Configuration;

/// <summary>
/// Configuration options for the IDMT plugin
/// </summary>
public class IdmtOptions
{
    /// <summary>
    /// Application configuration options
    /// </summary>
    public ApplicationOptions Application { get; set; } = new();

    /// <summary>
    /// Identity configuration options
    /// </summary>
    public IdentityOptions Identity { get; set; } = new();

    /// <summary>
    /// Multi-tenant configuration options
    /// </summary>
    public MultiTenantOptions MultiTenant { get; set; } = new();

    /// <summary>
    /// Database configuration options
    /// </summary>
    public DatabaseOptions Database { get; set; } = new();
}

/// <summary>
/// Application configuration options
/// </summary>
public class ApplicationOptions
{
    public const string PasswordResetEndpointName = "ResetPassword";
    public const string ConfirmEmailEndpointName = "ConfirmEmail";
    
    /// <summary>
    /// Base URL of the client application, if any (e.g. "https://myapp.com")
    /// </summary>
    public string? ClientUrl { get; set; }
    
    public string ResetPasswordFormPath { get; set; } = "/reset-password";
    public string ConfirmEmailFormPath { get; set; } = "/confirm-email";
}

/// <summary>
/// ASP.NET Core Identity configuration
/// </summary>
public class IdentityOptions
{
    /// <summary>
    /// Password requirements
    /// </summary>
    public PasswordOptions Password { get; set; } = new();

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
    public CookieOptions Cookie { get; set; } = new();

    /// <summary>
    /// Role configuration options
    /// </summary>
    public string[] ExtraRoles { get; set; } = [];
}

/// <summary>
/// Password configuration options
/// </summary>
public class PasswordOptions
{
    public bool RequireDigit { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; } = false;
    public int RequiredLength { get; set; } = 6;
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
    public bool RequireConfirmedEmail { get; set; } = false;
    public bool RequireConfirmedPhoneNumber { get; set; } = false;
}

/// <summary>
/// Cookie configuration options
/// </summary>
public class CookieOptions
{
    public string Name { get; set; } = ".Idmt.Application";
    public bool HttpOnly { get; set; } = true;
    public Microsoft.AspNetCore.Http.CookieSecurePolicy SecurePolicy { get; set; } = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
    public Microsoft.AspNetCore.Http.SameSiteMode SameSite { get; set; } = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromDays(14);
    public bool SlidingExpiration { get; set; } = true;
    public string LoginPath { get; set; } = "/login";
    public string LogoutPath { get; set; } = "/logout";
    public string AccessDeniedPath { get; set; } = "/access-denied";
}

public static class IdmtMultiTenantStrategy
{
    public const string Header = "header";
    public const string Claim = "claim";
    public const string Route = "route";
    public const string BasePath = "basepath";

    public const string DefaultHeaderName = "__tenant__";
    public const string DefaultClaimType = "tenant";
    public const string DefaultRouteParameter = "__tenant__";
}

/// <summary>
/// Multi-tenant configuration options
/// </summary>
public class MultiTenantOptions
{
    /// <summary>
    /// Default tenant ID for fallback
    /// </summary>
    public const string DefaultTenantId = "system-tenant";

    /// <summary>
    /// Tenant resolution strategy (header, subdomain, etc.)
    /// </summary>
    public string[] Strategies { get; set; } = [IdmtMultiTenantStrategy.Header, IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.Route];

    /// <summary>
    /// Strategy-specific configuration
    /// </summary>
    public Dictionary<string, string> StrategyOptions { get; set; } = [];
}

/// <summary>
/// Database configuration options
/// </summary>
public class DatabaseOptions
{
    /// <summary>
    /// Connection string template with placeholder for tenant's properties
    /// </summary>
    public string ConnectionStringTemplate { get; set; } = string.Empty;

    /// <summary>
    /// Auto-migrate database on startup
    /// </summary>
    public bool AutoMigrate { get; set; } = false;
}