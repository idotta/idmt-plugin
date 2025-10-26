namespace Idotta.Idmt.Plugin.Configuration;

/// <summary>
/// Configuration options for the IDMT plugin
/// </summary>
public class IdmtOptions
{
    /// <summary>
    /// JWT configuration options
    /// </summary>
    public JwtOptions Jwt { get; set; } = new();

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
/// JWT authentication configuration
/// </summary>
public class JwtOptions
{
    /// <summary>
    /// JWT secret key
    /// </summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>
    /// JWT issuer
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// JWT audience
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// JWT expiration time in minutes
    /// </summary>
    public int ExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Refresh token expiration time in days
    /// </summary>
    public int RefreshTokenExpirationDays { get; set; } = 7;
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
/// Multi-tenant configuration options
/// </summary>
public class MultiTenantOptions
{
    /// <summary>
    /// Default tenant ID for fallback
    /// </summary>
    public string DefaultTenantId { get; set; } = "default";

    /// <summary>
    /// Tenant resolution strategy (header, subdomain, etc.)
    /// </summary>
    public string Strategy { get; set; } = "header";

    /// <summary>
    /// Strategy-specific configuration
    /// </summary>
    public Dictionary<string, string> StrategyOptions { get; set; } = new();
}

/// <summary>
/// Database configuration options
/// </summary>
public class DatabaseOptions
{
    /// <summary>
    /// Connection string template with placeholder for tenant
    /// </summary>
    public string ConnectionStringTemplate { get; set; } = string.Empty;

    /// <summary>
    /// Whether to use shared database with tenant isolation
    /// </summary>
    public bool UseSharedDatabase { get; set; } = true;

    /// <summary>
    /// Auto-migrate database on startup
    /// </summary>
    public bool AutoMigrate { get; set; } = false;
}