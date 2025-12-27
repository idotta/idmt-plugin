using System.Text.Encodings.Web;
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
        Task<Result> HandleAsync(
            bool useApiLinks,
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
        public async Task<Result> HandleAsync(
            bool useApiLinks,
            ResendConfirmationEmailRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null || !user.IsActive)
                {
                    // Don't reveal whether user exists for security
                    return Result.Success(StatusCodes.Status200OK);
                }

                if (user.EmailConfirmed)
                {
                    return Result.Success(StatusCodes.Status200OK);
                }

                // Generate email confirmation token
                string token = await userManager.GenerateEmailConfirmationTokenAsync(user);

                string confirmEmailUrl = useApiLinks
                    ? linkGenerator.GenerateConfirmEmailApiLink(request.Email, token)
                    : linkGenerator.GenerateConfirmEmailFormLink(request.Email, token);

                await emailSender.SendConfirmationLinkAsync(user, request.Email, HtmlEncoder.Default.Encode(confirmEmailUrl));

                return Result.Success(StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error resending confirmation email to {Email}", request.Email);
                return Result.Failure($"An error occurred while resending confirmation email: {ex.Message}", StatusCodes.Status500InternalServerError);
            }
        }
    }

    public static Dictionary<string, string[]>? Validate(this ResendConfirmationEmailRequest request)
    {
        if (!Validators.IsValidEmail(request.Email))
        {
            return new Dictionary<string, string[]>
            {
                ["Email"] = ["Invalid email address."]
            };
        }

        return null;
    }

    public static RouteHandlerBuilder MapResendConfirmationEmailEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/resendConfirmationEmail", async Task<Results<Ok, ValidationProblem, InternalServerError>> (
            [FromQuery] bool useApiLinks,
            [FromBody] ResendConfirmationEmailRequest request,
            [FromServices] IResendConfirmationEmailHandler handler,
            HttpContext context) =>
        {
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var result = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
            if (!result.IsSuccess)
            {
                return TypedResults.InternalServerError();
            }

            return TypedResults.Ok();
        })
        .WithSummary("Resend confirmation email")
        .WithDescription("Resend email confirmation link");
    }
}
