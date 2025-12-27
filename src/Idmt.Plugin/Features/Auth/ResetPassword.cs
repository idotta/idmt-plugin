using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class ResetPassword
{
    public sealed record ResetPasswordRequest(string NewPassword);

    public interface IResetPasswordHandler
    {
        Task<Result> HandleAsync(string tenantIdentifier, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResetPasswordHandler(IServiceProvider serviceProvider) : IResetPasswordHandler
    {
        public async Task<Result> HandleAsync(string tenantIdentifier, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default)
        {
            using var scope = serviceProvider.CreateScope();
            var provider = scope.ServiceProvider;

            var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
            if (tenantInfo is null || !tenantInfo.IsActive)
            {
                return Result.Failure("Invalid tenant", StatusCodes.Status400BadRequest);
            }
            // Set Tenant Context BEFORE resolving DbContext/Managers
            var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
            var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
            tenantContextSetter.MultiTenantContext = tenantContext;

            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
            try
            {
                var user = await userManager.FindByEmailAsync(email);
                if (user is null)
                {
                    // Avoid revealing that the email does not exist
                    return Result.Failure("User not found", StatusCodes.Status400BadRequest);
                }

                // Reset password using the token
                var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

                if (!result.Succeeded)
                {
                    var errors = string.Join("\n", result.Errors.Select(e => e.Description));
                    return Result.Failure(errors, StatusCodes.Status400BadRequest);
                }

                if (!user.EmailConfirmed)
                {
                    user.EmailConfirmed = true;
                    await userManager.UpdateAsync(user);
                }

                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while resetting the password: {ex.Message}", StatusCodes.Status500InternalServerError);
            }
        }
    }

    public static Dictionary<string, string[]>? Validate(this ResetPasswordRequest request, string tenantIdentifier, string email, string token, Configuration.PasswordOptions options)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrEmpty(tenantIdentifier))
        {
            errors["TenantIdentifier"] = ["Tenant ID is required"];
        }
        if (!Validators.IsValidEmail(email))
        {
            errors["Email"] = ["Invalid email address."];
        }
        if (string.IsNullOrEmpty(token))
        {
            errors["Token"] = ["Token is required"];
        }
        if (!Validators.IsValidNewPassword(request.NewPassword, options, out var newPasswordErrors))
        {
            errors["NewPassword"] = newPasswordErrors ?? [];
        }

        return errors.Count == 0 ? null : errors;
    }

    public static RouteHandlerBuilder MapResetPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/resetPassword", async Task<Results<Ok, ValidationProblem, BadRequest>> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromBody] ResetPasswordRequest request,
            [FromServices] IResetPasswordHandler handler,
            [FromServices] IOptions<IdmtOptions> options,
            HttpContext context) =>
        {
            if (request.Validate(tenantIdentifier, email, token, options.Value.Identity.Password) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var result = await handler.HandleAsync(tenantIdentifier, email, token, request, cancellationToken: context.RequestAborted);
            if (!result.IsSuccess)
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
        return endpoints.MapGet("/resetPassword", Results<RedirectHttpResult, ProblemHttpResult> (
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