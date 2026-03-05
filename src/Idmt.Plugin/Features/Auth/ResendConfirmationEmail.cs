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
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class ResendConfirmationEmail
{
    public sealed record ResendConfirmationEmailRequest(string Email);

    public interface IResendConfirmationEmailHandler
    {
        Task<ErrorOr<Success>> HandleAsync(
            ResendConfirmationEmailRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class ResendConfirmationEmailHandler(
        UserManager<IdmtUser> userManager,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender,
        ILogger<ResendConfirmationEmailHandler> logger
        ) : IResendConfirmationEmailHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(
            ResendConfirmationEmailRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null || !user.IsActive)
                {
                    // Don't reveal whether user exists for security
                    return Result.Success;
                }

                if (user.EmailConfirmed)
                {
                    return Result.Success;
                }

                // Generate email confirmation token
                string token = await userManager.GenerateEmailConfirmationTokenAsync(user);

                string confirmEmailUrl = linkGenerator.GenerateConfirmEmailLink(request.Email, token);

                await emailSender.SendConfirmationLinkAsync(user, request.Email, confirmEmailUrl);

                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error resending confirmation email to {Email}", PiiMasker.MaskEmail(request.Email));
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapResendConfirmationEmailEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/resend-confirmation-email", async Task<Results<Ok, ValidationProblem, InternalServerError>> (
            [FromBody] ResendConfirmationEmailRequest request,
            [FromServices] IResendConfirmationEmailHandler handler,
            [FromServices] IValidator<ResendConfirmationEmailRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return TypedResults.InternalServerError();
            }

            return TypedResults.Ok();
        })
        .WithSummary("Resend confirmation email")
        .WithDescription("Resend email confirmation link");
    }
}
