using Idmt.Plugin.Validation;

namespace Idmt.Plugin.Features.Login;

public sealed record LoginRequest
{
    public required string EmailOrUsername { get; init; }
    public required string Password { get; init; }
    public string? TwoFactorCode { get; init; }
    public string? TwoFactorRecoveryCode { get; init; }
}

public static class LoginRequestValidator
{
    /// <summary>
    /// Validate the login request.
    /// </summary>
    /// <returns>A list of validation errors or null if the request is valid.</returns>
    public static Dictionary<string, string>? Validate(this LoginRequest request)
    {
        var errors = new Dictionary<string, string>();

        if (!Validators.IsValidEmailOrUsername(request.EmailOrUsername))
        {
            errors["EmailOrUsername"] = "Invalid email or username.";
        }

        if (!Validators.IsValidPassword(request.Password))
        {
            errors["Password"] = "Invalid password.";
        }

        return errors.Count == 0 ? null : errors;
    }
}
