using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Auth;

public static class ForgotPassword
{
    public sealed record ForgotPasswordRequest(string Email);

    public sealed record ForgotPasswordResponse;

    public interface IForgotPasswordHandler
    {
        Task<ErrorOr<ForgotPasswordResponse>> HandleAsync(
            ForgotPasswordRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class ForgotPasswordHandler(
        UserManager<IdmtUser> userManager,
        IEmailSender<IdmtUser> emailSender,
        IIdmtLinkGenerator linkGenerator,
        ILogger<ForgotPasswordHandler> logger) : IForgotPasswordHandler
    {
        public async Task<ErrorOr<ForgotPasswordResponse>> HandleAsync(
            ForgotPasswordRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null || !user.IsActive)
                {
                    // Don't reveal whether user exists or not for security
                    return new ForgotPasswordResponse();
                }

                // Generate password reset token
                var token = await userManager.GeneratePasswordResetTokenAsync(user);

                // Generate password reset link (always client form URL)
                var resetUrl = linkGenerator.GeneratePasswordResetLink(user.Email!, token);

                // Send email with reset code
                await emailSender.SendPasswordResetCodeAsync(user, request.Email, resetUrl);

                return new ForgotPasswordResponse();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during forgot password for {Email}",
                    request.Email.Length > 3 ? string.Concat(request.Email.AsSpan(0, 3), "***") : "***");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapForgotPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/forgot-password", async Task<Results<Ok, ValidationProblem, StatusCodeHttpResult>> (
            [FromBody] ForgotPasswordRequest request,
            [FromServices] IForgotPasswordHandler handler,
            [FromServices] IValidator<ForgotPasswordRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return TypedResults.StatusCode(StatusCodes.Status500InternalServerError);
            }
            return TypedResults.Ok();
        })
        .WithSummary("Forgot password")
        .WithDescription("Initiate password reset process");
    }
}
