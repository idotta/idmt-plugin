using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class ResetPassword
{
    public sealed record ResetPasswordRequest(string NewPassword);

    public interface IResetPasswordHandler
    {
        Task<ErrorOr<Success>> HandleAsync(string tenantIdentifier, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResetPasswordHandler(
        ITenantOperationService tenantOps,
        ILogger<ResetPasswordHandler> logger) : IResetPasswordHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(string tenantIdentifier, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default)
        {
            return await tenantOps.ExecuteInTenantScopeAsync(tenantIdentifier, async provider =>
            {
                var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var user = await userManager.FindByEmailAsync(email);
                    if (user is null || !user.IsActive)
                    {
                        return IdmtErrors.Password.ResetFailed;
                    }

                    var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

                    if (!result.Succeeded)
                    {
                        return IdmtErrors.Password.ResetFailed;
                    }

                    if (!user.EmailConfirmed)
                    {
                        user.EmailConfirmed = true;
                        await userManager.UpdateAsync(user);
                    }

                    return Result.Success;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "An error occurred during password reset for {Email}",
                        email.Length > 3 ? string.Concat(email.AsSpan(0, 3), "***") : "***");
                    return IdmtErrors.General.Unexpected;
                }
            });
        }
    }

    public static RouteHandlerBuilder MapResetPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/reset-password", async Task<Results<Ok, ValidationProblem, BadRequest>> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromBody] ResetPasswordRequest request,
            [FromServices] IResetPasswordHandler handler,
            [FromServices] IValidator<ResetPasswordRequest> validator,
            HttpContext context) =>
        {
            // Validate query parameters
            var queryErrors = new Dictionary<string, string[]>();
            if (string.IsNullOrEmpty(tenantIdentifier))
                queryErrors["tenantIdentifier"] = ["Tenant identifier is required"];
            if (!Validators.IsValidEmail(email))
                queryErrors["email"] = ["Invalid email address."];
            if (string.IsNullOrEmpty(token))
                queryErrors["token"] = ["Token is required"];
            if (queryErrors.Count > 0)
                return TypedResults.ValidationProblem(queryErrors);

            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var result = await handler.HandleAsync(tenantIdentifier, email, token, request, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return TypedResults.BadRequest();
            }
            return TypedResults.Ok();
        })
        .WithName(ApplicationOptions.PasswordResetEndpointName)
        .WithSummary("Reset password")
        .WithDescription("Reset password using reset token");
    }

    public static RouteHandlerBuilder MapResetPasswordRedirectEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/reset-password", Results<RedirectHttpResult, ProblemHttpResult> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromServices] IOptions<IdmtOptions> options,
            HttpContext context) =>
        {
            var clientUrl = options.Value.Application.ClientUrl;
            var resetPasswordPath = options.Value.Application.ResetPasswordFormPath;

            if (string.IsNullOrEmpty(clientUrl))
            {
                return TypedResults.Problem("Client URL is not configured.");
            }

            var queryParams = new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = tenantIdentifier,
                ["email"] = email,
                ["token"] = token
            };

            var uri = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(
                $"{clientUrl.TrimEnd('/')}/{resetPasswordPath.TrimStart('/')}",
                queryParams);

            return TypedResults.Redirect(uri);
        })
        .WithName(ApplicationOptions.PasswordResetEndpointName + "-form")
        .WithSummary("Redirect to reset password form")
        .WithDescription("Redirect to reset password form");
    }
}
