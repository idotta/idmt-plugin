using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using FluentValidation;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class Login
{
    public sealed record LoginRequest
    {
        public string? Email { get; init; }
        public string? Username { get; init; }
        public required string Password { get; init; }
        public bool RememberMe { get; init; }
        public string? TwoFactorCode { get; init; }
        public string? TwoFactorRecoveryCode { get; init; }
    }

    public sealed record LoginResponse
    {
        public Guid? UserId { get; init; }
    }

    public sealed record AccessTokenResponse
    {
        public required string AccessToken { get; init; }
        public required string RefreshToken { get; init; }
        public required long ExpiresIn { get; init; }
        public required string TokenType { get; init; } = "Bearer";
    }

    public interface ILoginHandler
    {
        Task<ErrorOr<LoginResponse>> HandleAsync(
            LoginRequest loginRequest,
            CancellationToken cancellationToken = default);
    }

    public interface ITokenLoginHandler
    {
        Task<ErrorOr<AccessTokenResponse>> HandleAsync(
            LoginRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class LoginHandler(
        UserManager<IdmtUser> userManager,
        SignInManager<IdmtUser> signInManager,
        IMultiTenantContextAccessor multiTenantContextAccessor,
        TimeProvider timeProvider,
        ILogger<LoginHandler> logger) : ILoginHandler
    {
        public async Task<ErrorOr<LoginResponse>> HandleAsync(
            LoginRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Resolve tenant ID from context
                var tenantInfo = multiTenantContextAccessor.MultiTenantContext?.TenantInfo;
                if (tenantInfo == null || string.IsNullOrEmpty(tenantInfo.Id))
                {
                    return IdmtErrors.Tenant.NotResolved;
                }

                // Find user by email or username
                // EF Core multi-tenant filtering automatically ensures user belongs to the current tenant
                IdmtUser? user = null;
                if (request.Email is not null)
                {
                    user = await userManager.FindByEmailAsync(request.Email);
                }
                else if (request.Username is not null)
                {
                    user = await userManager.FindByNameAsync(request.Username);
                }
                if (user == null)
                {
                    return IdmtErrors.Auth.Unauthorized;
                }

                var result = await signInManager.CheckPasswordSignInAsync(
                    user,
                    request.Password,
                    lockoutOnFailure: true);

                if (result.RequiresTwoFactor)
                {
                    if (!string.IsNullOrEmpty(request.TwoFactorCode))
                    {
                        result = await signInManager.TwoFactorAuthenticatorSignInAsync(request.TwoFactorCode, request.RememberMe, request.RememberMe);
                    }
                    else if (!string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
                    {
                        result = await signInManager.TwoFactorRecoveryCodeSignInAsync(request.TwoFactorRecoveryCode);
                    }
                }

                if (!result.Succeeded)
                {
                    return IdmtErrors.Auth.Unauthorized;
                }

                // Check if user is active
                if (!user.IsActive)
                {
                    logger.LogWarning("Login attempt failed: User {UserId} is inactive", user.Id);
                    return IdmtErrors.Auth.UserDeactivated;
                }

                // Direct cookie sign-in (no middleware delay)
                var principal = await signInManager.CreateUserPrincipalAsync(user);
                await signInManager.Context.SignInAsync(
                    IdentityConstants.ApplicationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = request.RememberMe,
                        ExpiresUtc = timeProvider.GetUtcNow().AddDays(30)
                    });

                // Update last login timestamp
                user.LastLoginAt = timeProvider.GetUtcNow().UtcDateTime;
                await userManager.UpdateAsync(user);

                return new LoginResponse { UserId = user.Id };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during login for identifier {Email} {Username}", request.Email ?? "unknown", request.Username ?? "unknown");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    internal sealed class TokenLoginHandler(
        UserManager<IdmtUser> userManager,
        SignInManager<IdmtUser> signInManager,
        IMultiTenantContextAccessor multiTenantContextAccessor,
        IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
        TimeProvider timeProvider,
        ILogger<TokenLoginHandler> logger) : ITokenLoginHandler
    {
        public async Task<ErrorOr<AccessTokenResponse>> HandleAsync(
            LoginRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Resolve tenant ID from context
                var tenantInfo = multiTenantContextAccessor.MultiTenantContext?.TenantInfo;
                if (tenantInfo == null || string.IsNullOrEmpty(tenantInfo.Id))
                {
                    return IdmtErrors.Tenant.NotResolved;
                }

                // Find user by email or username
                // EF Core multi-tenant filtering automatically ensures user belongs to the current tenant
                IdmtUser? user = null;
                if (request.Email is not null)
                {
                    user = await userManager.FindByEmailAsync(request.Email);
                }
                else if (request.Username is not null)
                {
                    user = await userManager.FindByNameAsync(request.Username);
                }
                if (user == null)
                {
                    return IdmtErrors.Auth.Unauthorized;
                }

                var result = await signInManager.CheckPasswordSignInAsync(
                    user,
                    request.Password,
                    lockoutOnFailure: true);

                if (result.RequiresTwoFactor)
                {
                    if (!string.IsNullOrEmpty(request.TwoFactorCode))
                    {
                        result = await signInManager.TwoFactorAuthenticatorSignInAsync(request.TwoFactorCode, request.RememberMe, request.RememberMe);
                    }
                    else if (!string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
                    {
                        result = await signInManager.TwoFactorRecoveryCodeSignInAsync(request.TwoFactorRecoveryCode);
                    }
                }

                if (!result.Succeeded)
                {
                    return IdmtErrors.Auth.Unauthorized;
                }

                // Check if user is active
                if (!user.IsActive)
                {
                    logger.LogWarning("Login attempt failed: User {UserId} is inactive", user.Id);
                    return IdmtErrors.Auth.UserDeactivated;
                }

                // Generate tokens using BearerToken
                var principal = await signInManager.CreateUserPrincipalAsync(user);
                var bearerOptions = bearerTokenOptions.Get(IdentityConstants.BearerScheme);
                var now = timeProvider.GetUtcNow();
                var expiresUtc = now.Add(bearerOptions.BearerTokenExpiration);
                var refreshExpiresUtc = now.Add(bearerOptions.RefreshTokenExpiration);

                var authProperties = new AuthenticationProperties
                {
                    ExpiresUtc = expiresUtc,
                    IsPersistent = request.RememberMe
                };

                var authTicket = new AuthenticationTicket(principal, authProperties, IdentityConstants.BearerScheme);

                // Generate access token
                var accessTokenProtector = bearerOptions.BearerTokenProtector;
                var accessToken = accessTokenProtector.Protect(authTicket);

                // Generate refresh token
                var refreshProperties = new AuthenticationProperties
                {
                    ExpiresUtc = refreshExpiresUtc,
                    IsPersistent = request.RememberMe
                };
                var refreshTicket = new AuthenticationTicket(principal, refreshProperties, IdentityConstants.BearerScheme);
                var refreshTokenProtector = bearerOptions.RefreshTokenProtector;
                var refreshToken = refreshTokenProtector.Protect(refreshTicket);

                // Update last login timestamp
                user.LastLoginAt = timeProvider.GetUtcNow().UtcDateTime;
                await userManager.UpdateAsync(user);

                var expiresIn = (long)bearerOptions.BearerTokenExpiration.TotalSeconds;

                return new AccessTokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during login for identifier {Email} {Username}", request.Email ?? request.Username ?? "unknown", request.Email ?? request.Username ?? "unknown");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapCookieLoginEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/login", async Task<Results<Ok<LoginResponse>, UnauthorizedHttpResult, ForbidHttpResult, ValidationProblem, ProblemHttpResult>> (
            [FromBody] LoginRequest request,
            [FromServices] ILoginHandler handler,
            [FromServices] IValidator<LoginRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (response.IsError)
            {
                return response.FirstError.Type switch
                {
                    ErrorType.Unauthorized => TypedResults.Unauthorized(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    _ => TypedResults.Problem(response.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError),
                };
            }
            return TypedResults.Ok(response.Value);
        })
        .WithSummary("Login user")
        .WithDescription("Authenticate user and return cookie");
    }

    public static RouteHandlerBuilder MapTokenLoginEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/token", async Task<Results<Ok<AccessTokenResponse>, UnauthorizedHttpResult, ForbidHttpResult, ValidationProblem, ProblemHttpResult>> (
            [FromBody] LoginRequest request,
            [FromServices] ITokenLoginHandler handler,
            [FromServices] IValidator<LoginRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (response.IsError)
            {
                return response.FirstError.Type switch
                {
                    ErrorType.Unauthorized => TypedResults.Unauthorized(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    _ => TypedResults.Problem(response.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError),
                };
            }
            return TypedResults.Ok(response.Value);
        })
        .WithSummary("Login user")
        .WithDescription("Authenticate user and return bearer token");
    }
}
