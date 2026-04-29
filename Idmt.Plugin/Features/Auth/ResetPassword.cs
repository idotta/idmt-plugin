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
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class ResetPassword
{
    public sealed record ResetPasswordRequest(string Email, string Token, string NewPassword);

    public interface IResetPasswordHandler
    {
        Task<ErrorOr<Success>> HandleAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResetPasswordHandler(
        UserManager<IdmtUser> userManager,
        ILogger<ResetPasswordHandler> logger) : IResetPasswordHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user is null || !user.IsActive)
                {
                    return IdmtErrors.Password.ResetFailed;
                }

                var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

                if (!result.Succeeded)
                {
                    return IdmtErrors.Password.ResetFailed;
                }

                // Note: Per security audit C7, password reset proves possession of the
                // current Email mailbox at token-issue time only. Do NOT mutate
                // EmailConfirmed here — that flag must be set exclusively via the
                // ConfirmEmail flow.
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during password reset for {Email}", PiiMasker.MaskEmail(request.Email));
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapResetPasswordEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/reset-password", async Task<Results<Ok, ValidationProblem, BadRequest>> (
            [FromBody] ResetPasswordRequest request,
            [FromServices] IResetPasswordHandler handler,
            [FromServices] IValidator<ResetPasswordRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            // Decode Base64URL-encoded token
            string decodedToken;
            try
            {
                decodedToken = Base64Service.DecodeBase64UrlToken(request.Token);
            }
            catch (FormatException)
            {
                return TypedResults.BadRequest();
            }

            var decodedRequest = request with { Token = decodedToken };
            var result = await handler.HandleAsync(decodedRequest, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return TypedResults.BadRequest();
            }
            return TypedResults.Ok();
        })
        .WithName(IdmtEndpointNames.PasswordReset)
        .WithSummary("Reset password")
        .WithDescription("Reset password using reset token");
    }
}
