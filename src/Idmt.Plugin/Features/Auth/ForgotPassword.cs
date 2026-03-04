using ErrorOr;
using FluentValidation;
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

namespace Idmt.Plugin.Features.Auth;

public static class ForgotPassword
{
    public sealed record ForgotPasswordRequest(string Email);

    public sealed record ForgotPasswordResponse;

    public interface IForgotPasswordHandler
    {
        Task<ErrorOr<ForgotPasswordResponse>> HandleAsync(
            bool useApiLinks,
            ForgotPasswordRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class ForgotPasswordHandler(
        UserManager<IdmtUser> userManager,
        IEmailSender<IdmtUser> emailSender,
        IIdmtLinkGenerator linkGenerator) : IForgotPasswordHandler
    {
        public async Task<ErrorOr<ForgotPasswordResponse>> HandleAsync(
            bool useApiLinks,
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

                // Generate password reset link
                var resetUrl = useApiLinks
                    ? linkGenerator.GeneratePasswordResetApiLink(user.Email!, token)
                    : linkGenerator.GeneratePasswordResetFormLink(user.Email!, token);

                // Send email with reset code
                await emailSender.SendPasswordResetCodeAsync(user, request.Email, resetUrl);

                return new ForgotPasswordResponse();
            }
            catch (Exception)
            {
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapForgotPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/forgot-password", async Task<Results<Ok, ValidationProblem, StatusCodeHttpResult>> (
            [FromQuery] bool useApiLinks,
            [FromBody] ForgotPasswordRequest request,
            [FromServices] IForgotPasswordHandler handler,
            [FromServices] IValidator<ForgotPasswordRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var result = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
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
