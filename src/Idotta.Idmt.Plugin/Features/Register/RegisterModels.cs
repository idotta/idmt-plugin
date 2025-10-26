using System.ComponentModel.DataAnnotations;

namespace Idotta.Idmt.Plugin.Features.Register;

/// <summary>
/// User registration request model
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// User email address
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Password confirmation
    /// </summary>
    [Required]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// User's first name
    /// </summary>
    [Required]
    [StringLength(50)]
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// User's last name
    /// </summary>
    [Required]
    [StringLength(50)]
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Optional phone number
    /// </summary>
    [Phone]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Optional tenant identifier
    /// </summary>
    public string? TenantId { get; set; }
}

/// <summary>
/// User registration response model
/// </summary>
public class RegisterResponse
{
    /// <summary>
    /// Indicates if registration was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Created user ID
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// Success message
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Error message if registration failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// List of validation errors
    /// </summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// Whether email confirmation is required
    /// </summary>
    public bool RequiresEmailConfirmation { get; set; }

    /// <summary>
    /// Email confirmation token (if required)
    /// </summary>
    public string? EmailConfirmationToken { get; set; }
}