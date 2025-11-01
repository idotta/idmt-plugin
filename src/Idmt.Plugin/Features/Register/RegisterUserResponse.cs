using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Response model for user registration operations. Contains the result of the registration attempt,
/// including success status, user identifier, password setup token, and any validation or error messages.
/// </summary>
public sealed record RegisterUserResponse
{
    /// <summary>
    /// Indicates whether the registration operation succeeded.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// The unique identifier of the created user (as string). Only populated when Success is true.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// Password reset token that can be used to set the user's initial password.
    /// This token is generated using ASP.NET Core Identity's password reset token mechanism.
    /// Only populated when Success is true.
    /// </summary>
    public string? PasswordSetupToken { get; init; }

    /// <summary>
    /// Fully constructed URL for password setup if Application.BaseUrl is configured.
    /// Contains the email and token as query parameters. Only populated when Success is true and BaseUrl is configured.
    /// </summary>
    public string? PasswordSetupUrl { get; init; }

    /// <summary>
    /// HTTP status code for the response. Defaults to 201 Created for successful registrations,
    /// 400 Bad Request for validation errors or failures.
    /// </summary>
    public int StatusCode { get; init; } = StatusCodes.Status201Created;

    /// <summary>
    /// General error message when registration fails. Used for non-validation errors.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Dictionary of field-specific validation errors. Key is the field name, value is the error message.
    /// Only populated when validation fails or Identity operations return errors.
    /// </summary>
    public Dictionary<string, string>? ValidationErrors { get; init; }
}
