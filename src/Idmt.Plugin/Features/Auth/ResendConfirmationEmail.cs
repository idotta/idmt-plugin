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

namespace Idmt.Plugin.Features.Auth;

public static class ResendConfirmationEmail
{
    public sealed record ResendConfirmationEmailRequest(string Email);

    public sealed record ResendConfirmationEmailResponse(bool Success, string? ConfirmationToken = null, string? ConfirmationUrl = null, string? Message = null);

    public interface IResendConfirmationEmailHandler
    {
        Task<ResendConfirmationEmailResponse> HandleAsync(
            bool useApiLinks,
            ResendConfirmationEmailRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class ResendConfirmationEmailHandler(
        UserManager<IdmtUser> userManager,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender
        ) : IResendConfirmationEmailHandler
    {
        public async Task<ResendConfirmationEmailResponse> HandleAsync(
            bool useApiLinks,
            ResendConfirmationEmailRequest request,
            CancellationToken cancellationToken = default)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive)
            {
                // Don't reveal whether user exists for security
                return new ResendConfirmationEmailResponse(true, Message: "If the email exists, a confirmation link has been sent.");
            }

            if (user.EmailConfirmed)
            {
                return new ResendConfirmationEmailResponse(true, Message: "Email is already confirmed.");
            }

            // Generate email confirmation token
            string token = await userManager.GenerateEmailConfirmationTokenAsync(user);

            string confirmEmailUrl = useApiLinks
                ? linkGenerator.GenerateConfirmEmailApiLink(request.Email, token)
                : linkGenerator.GenerateConfirmEmailFormLink(request.Email, token);

            await emailSender.SendConfirmationLinkAsync(user, request.Email, HtmlEncoder.Default.Encode(confirmEmailUrl));

            return new ResendConfirmationEmailResponse(true, token, confirmEmailUrl, "If the email exists, a confirmation link has been sent.");
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
        return endpoints.MapPost("/resendConfirmationEmail", async Task<Results<Ok<ResendConfirmationEmailResponse>, ValidationProblem>> (
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
            return TypedResults.Ok(result);
        })
        .WithSummary("Resend confirmation email")
        .WithDescription("Resend email confirmation link");
    }
}
