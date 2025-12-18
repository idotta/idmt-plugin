using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Idmt.Plugin.Configuration;

namespace Idmt.Plugin.Validation;

/// <summary>
/// Common validation utilities for the application.
/// </summary>
public static partial class Validators
{
    private static readonly EmailAddressAttribute EmailValidator = new();

    [GeneratedRegex(@"\d", RegexOptions.Compiled)]
    public static partial Regex OneDigitRegex();

    [GeneratedRegex("[a-z]", RegexOptions.Compiled)]
    public static partial Regex OneLowercaseRegex();

    [GeneratedRegex("[A-Z]", RegexOptions.Compiled)]
    public static partial Regex OneUppercaseRegex();

    [GeneratedRegex(@"[^a-zA-Z0-9]", RegexOptions.Compiled)]
    public static partial Regex OneNonAlphaRegex();

    /// <summary>
    /// Validates an email address.
    /// </summary>
    public static bool IsValidEmail(string? email)
    {
        return !string.IsNullOrWhiteSpace(email) && EmailValidator.IsValid(email);
    }

    /// <summary>
    /// Validates a new password meets security requirements.
    /// </summary>
    /// <param name="password">The password to validate.</param>
    /// <param name="options">The password options to use.</param>
    /// <param name="errors">The list of errors if the password is invalid.</param>
    /// <param name="options"></param>
    /// <returns>True if the password is valid, false otherwise.</returns>
    public static bool IsValidNewPassword(string? password, PasswordOptions options, out string[]? errors)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            errors = ["Password is required"];
            return false;
        }

        // Build password validation regex and check requirements based on provided options
        var errorList = new List<string>();

        if (password.Length < options.RequiredLength)
        {
            errorList.Add($"Password must be at least {options.RequiredLength} characters long.");
        }

        if (options.RequireDigit && !OneDigitRegex().IsMatch(password))
        {
            errorList.Add("Password must contain at least one digit.");
        }

        if (options.RequireLowercase && !OneLowercaseRegex().IsMatch(password))
        {
            errorList.Add("Password must contain at least one lowercase letter.");
        }

        if (options.RequireUppercase && !OneUppercaseRegex().IsMatch(password))
        {
            errorList.Add("Password must contain at least one uppercase letter.");
        }

        if (options.RequireNonAlphanumeric && !OneNonAlphaRegex().IsMatch(password))
        {
            errorList.Add("Password must contain at least one non-alphanumeric character.");
        }

        if (options.RequiredUniqueChars > 1)
        {
            var uniqueCharCount = new HashSet<char>(password).Count;
            if (uniqueCharCount < options.RequiredUniqueChars)
            {
                errorList.Add($"Password must contain at least {options.RequiredUniqueChars} unique characters.");
            }
        }

        if (errorList.Count > 0)
        {
            errors = [.. errorList];
            return false;
        }

        errors = null;
        return true;
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
        return !string.IsNullOrWhiteSpace(tenantId) && tenantId.Length >= 3;
    }

    /// <summary>
    /// Validates a username (non-empty string with minimum 3 characters).
    /// </summary>
    public static bool IsValidUsername(string? username)
    {
        return !string.IsNullOrWhiteSpace(username) && username.Length >= 3;
    }
}