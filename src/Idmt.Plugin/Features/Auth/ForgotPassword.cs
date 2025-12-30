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

public static class ForgotPassword
{
    public sealed record ForgotPasswordRequest(string Email);

    public sealed record ForgotPasswordResponse(string? ResetToken = null, string? ResetUrl = null);

    public interface IForgotPasswordHandler
    {
        Task<Result<ForgotPasswordResponse>> HandleAsync(
            bool useApiLinks,
            ForgotPasswordRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class ForgotPasswordHandler(
        UserManager<IdmtUser> userManager,
        IEmailSender<IdmtUser> emailSender,
        IIdmtLinkGenerator linkGenerator) : IForgotPasswordHandler
    {
        public async Task<Result<ForgotPasswordResponse>> HandleAsync(
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
                    return Result.Success(new ForgotPasswordResponse(null, null), StatusCodes.Status200OK);
                }

                // Generate password reset token
                var token = await userManager.GeneratePasswordResetTokenAsync(user);

                // Generate password reset link
                var resetUrl = useApiLinks
                    ? linkGenerator.GeneratePasswordResetApiLink(user.Email!, token)
                    : linkGenerator.GeneratePasswordResetFormLink(user.Email!, token);

                System.Diagnostics.Debug.WriteLine($"Password reset token for {user.Email}: {token}");

                // Send email with reset code
                await emailSender.SendPasswordResetCodeAsync(user, request.Email, resetUrl);

                return Result.Success(new ForgotPasswordResponse(token, resetUrl), StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                return Result.Failure<ForgotPasswordResponse>(ex.Message, StatusCodes.Status500InternalServerError);
            }
        }
    }

    public static Dictionary<string, string[]>? Validate(this ForgotPasswordRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (!Validators.IsValidEmail(request.Email))
        {
            errors["Email"] = ["Invalid email address."];
        }

        return errors.Count == 0 ? null : errors;
    }

    public static RouteHandlerBuilder MapForgotPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/forgotPassword", async Task<Results<Ok, ValidationProblem, StatusCodeHttpResult>> (
            [FromQuery] bool useApiLinks,
            [FromBody] ForgotPasswordRequest request,
            [FromServices] IForgotPasswordHandler handler,
            HttpContext context) =>
        {
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var result = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
            if (!result.IsSuccess)
            {
                return TypedResults.StatusCode(result.StatusCode);
            }
            return TypedResults.Ok();
        })
        .WithSummary("Forgot password")
        .WithDescription("Initiate password reset process");
    }
}
