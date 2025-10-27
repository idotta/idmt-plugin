using System.ComponentModel.DataAnnotations;

namespace Idmt.Plugin.Features.Login;

/// <summary>
/// Login request model
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// User email or username
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    [Required]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Remember user login
    /// </summary>
    public bool RememberMe { get; set; } = false;

    /// <summary>
    /// Optional tenant identifier
    /// </summary>
    public string? TenantId { get; set; }
}

/// <summary>
/// Login response model
/// </summary>
public class LoginResponse
{
    /// <summary>
    /// Indicates if login was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// JWT access token
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Refresh token
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Token expiration time
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// User information
    /// </summary>
    public UserInfo? User { get; set; }

    /// <summary>
    /// Error message if login failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// List of validation errors
    /// </summary>
    public List<string> Errors { get; set; } = new();
}

/// <summary>
/// User information model
/// </summary>
public class UserInfo
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? TenantId { get; set; }
    public List<string> Roles { get; set; } = new();
}