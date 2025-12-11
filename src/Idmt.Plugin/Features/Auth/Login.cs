using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class Login
{
    public sealed record LoginRequest
    {
        public required string EmailOrUsername { get; init; }
        public required string Password { get; init; }
        public string? TwoFactorCode { get; init; }
        public string? TwoFactorRecoveryCode { get; init; }
    }

    public sealed record LoginResponse
    {
        public bool Succeeded { get; init; }
        public bool IsLockedOut { get; init; }
        public bool IsNotAllowed { get; init; }
        public bool RequiresTwoFactor { get; init; }
        public int StatusCode { get; init; } = StatusCodes.Status401Unauthorized;
        public string? ErrorMessage { get; init; }
    }

    public interface ILoginHandler
    {
        Task<LoginResponse> HandleAsync(
            LoginRequest loginRequest,
            bool useCookies,
            bool useSessionCookies,
            CancellationToken cancellationToken = default);
    }

    internal sealed class LoginHandler(
        UserManager<IdmtUser> userManager,
        SignInManager<IdmtUser> signInManager,
        IMultiTenantContextAccessor multiTenantContextAccessor,
        ILogger<LoginHandler> logger) : ILoginHandler
    {
        public async Task<LoginResponse> HandleAsync(
            LoginRequest loginRequest,
            bool useCookies,
            bool useSessionCookies,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Resolve tenant ID from context
                var tenantInfo = multiTenantContextAccessor.MultiTenantContext?.TenantInfo;
                if (tenantInfo == null || string.IsNullOrEmpty(tenantInfo.Id))
                {
                    return new LoginResponse { ErrorMessage = "Tenant not resolved", StatusCode = StatusCodes.Status400BadRequest };
                }

                // Find user by email or username
                // EF Core multi-tenant filtering automatically ensures user belongs to the current tenant
                var user = await userManager.FindByEmailAsync(loginRequest.EmailOrUsername)
                    ?? await userManager.FindByNameAsync(loginRequest.EmailOrUsername);

                if (user == null)
                {
                    logger.LogWarning("Login attempt failed: User not found with identifier {EmailOrUsername}", loginRequest.EmailOrUsername);
                    return new LoginResponse { ErrorMessage = "Invalid email/username or password", StatusCode = StatusCodes.Status401Unauthorized };
                }

                // Check if user is active
                if (!user.IsActive)
                {
                    logger.LogWarning("Login attempt failed: User {UserId} is inactive", user.Id);
                    return new LoginResponse { ErrorMessage = "Account is inactive", StatusCode = StatusCodes.Status401Unauthorized };
                }

                // Sign in
                var useCookieScheme = useCookies == true || useSessionCookies == true;
                var isPersistent = useCookies == true && useSessionCookies != true;
                signInManager.AuthenticationScheme = useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

                var result = await signInManager.PasswordSignInAsync(loginRequest.EmailOrUsername, loginRequest.Password, isPersistent, lockoutOnFailure: true);

                if (result.RequiresTwoFactor)
                {
                    if (!string.IsNullOrEmpty(loginRequest.TwoFactorCode))
                    {
                        result = await signInManager.TwoFactorAuthenticatorSignInAsync(loginRequest.TwoFactorCode, isPersistent, rememberClient: isPersistent);
                    }
                    else if (!string.IsNullOrEmpty(loginRequest.TwoFactorRecoveryCode))
                    {
                        result = await signInManager.TwoFactorRecoveryCodeSignInAsync(loginRequest.TwoFactorRecoveryCode);
                    }
                }

                if (!result.Succeeded)
                {
                    return new LoginResponse
                    {
                        IsLockedOut = result.IsLockedOut,
                        IsNotAllowed = result.IsNotAllowed,
                        RequiresTwoFactor = result.RequiresTwoFactor,
                        ErrorMessage = result.ToString(),
                        StatusCode = StatusCodes.Status401Unauthorized
                    };
                }

                // Update last login timestamp
                user.LastLoginAt = DT.UtcNow;
                await userManager.UpdateAsync(user);

                logger.LogInformation("User {UserId} successfully logged in to tenant {TenantId}", user.Id, tenantInfo.Id);

                // The signInManager already produced the needed response in the form of a cookie or bearer token.
                return new LoginResponse { Succeeded = true, StatusCode = StatusCodes.Status200OK };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during login for identifier {EmailOrUsername}", loginRequest.EmailOrUsername);
                return new LoginResponse
                {
                    ErrorMessage = "An error occurred during login",
                    StatusCode = StatusCodes.Status500InternalServerError
                };
            }
        }

    }

    /// <summary>
    /// Validate the login request.
    /// </summary>
    /// <returns>A list of validation errors or null if the request is valid.</returns>
    public static Dictionary<string, string[]>? Validate(this LoginRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (!Validators.IsValidEmailOrUsername(request.EmailOrUsername))
        {
            errors["EmailOrUsername"] = ["Invalid email or username."];
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            errors["Password"] = ["Password is required."];
        }

        return errors.Count == 0 ? null : errors;
    }
}