using System.Text.RegularExpressions;
using Idmt.Plugin.Validation;

namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Request model for user registration. Represents the data required to create a new user account.
/// The user will be created without a password and will need to set it via the password setup token.
/// </summary>
public sealed record RegisterUserRequest
{
    /// <summary>
    /// Email address for the user. Required and must be a valid email format.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Optional username. If not provided, the email address will be used as the username.
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// Role name to assign to the user upon registration. Required and must be an existing role.
    /// </summary>
    public required string Role { get; init; }
}

/// <summary>
/// Extension methods for validating RegisterUserRequest instances.
/// Provides client-side and server-side validation of registration data.
/// </summary>
public static class RegisterUserRequestValidator
{
    /// <summary>
    /// Validates the registration request and returns a dictionary of validation errors if any exist.
    /// Returns null if validation passes.
    /// </summary>
    /// <param name="request">The registration request to validate</param>
    /// <returns>Dictionary of field names to error messages if validation fails, null if validation succeeds</returns>
    public static Dictionary<string, string>? Validate(this RegisterUserRequest request, string? allowedUsernameCharacters = null)
    {
        var errors = new Dictionary<string, string>();

        // Validate email format using standard email validation
        if (!Validators.IsValidEmail(request.Email))
        {
            errors["Email"] = "Invalid email address.";
        }

        // Validate username length if provided (minimum 3 characters)
        if (request.Username is not null)
        {
            if (!string.IsNullOrEmpty(allowedUsernameCharacters) && !Regex.IsMatch(request.Username, $"^[{allowedUsernameCharacters}]+$"))
            {
                errors["Username"] = $"Username must contain only the following characters: {allowedUsernameCharacters}";
            }
        }

        // Validate that role is provided and not empty
        if (string.IsNullOrEmpty(request.Role))
        {
            errors["Role"] = "Role is required.";
        }

        return errors.Count == 0 ? null : errors;
    }
}