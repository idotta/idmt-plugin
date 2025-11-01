using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Idmt.Plugin.Validation;

/// <summary>
/// Common validation utilities for the application.
/// </summary>
public static partial class Validators
{
    private static readonly EmailAddressAttribute EmailValidator = new();

    [GeneratedRegex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", RegexOptions.Compiled)]
    public static partial Regex PasswordRegex();

    /// <summary>
    /// Validates an email address.
    /// </summary>
    public static bool IsValidEmail(string? email)
    {
        return !string.IsNullOrWhiteSpace(email) && EmailValidator.IsValid(email);
    }

    /// <summary>
    /// Validates a password meets security requirements.
    /// </summary>
    public static bool IsValidPassword(string? password)
    {
        return !string.IsNullOrWhiteSpace(password) && PasswordRegex().IsMatch(password);
    }

    /// <summary>
    /// Validates a GUID string.
    /// </summary>
    public static bool IsValidGuid(string? guidString)
    {
        return !string.IsNullOrWhiteSpace(guidString) && Guid.TryParse(guidString, out _);
    }

    /// <summary>
    /// Validates a tenant ID (non-empty string).
    /// </summary>
    public static bool IsValidTenantId(string? tenantId)
    {
        return !string.IsNullOrWhiteSpace(tenantId);
    }

    /// <summary>
    /// Validates an email or username (non-empty string).
    /// </summary>
    public static bool IsValidEmailOrUsername(string? emailOrUsername)
    {
        return !string.IsNullOrWhiteSpace(emailOrUsername);
    }
}