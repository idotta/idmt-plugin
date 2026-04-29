using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class ConfirmEmailChange
{
    /// <summary>
    /// Request to confirm a previously staged out-of-band email change.
    /// Email is the user's CURRENT email (canonical lookup key).
    /// NewEmail is the staged value previously written to PendingEmail.
    /// Token is the change-email token issued by Identity at staging time.
    /// </summary>
    public sealed record ConfirmEmailChangeRequest(string Email, string NewEmail, string Token);

    public interface IConfirmEmailChangeHandler
    {
        Task<ErrorOr<Success>> HandleAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ConfirmEmailChangeHandler(
        UserManager<IdmtUser> userManager,
        IdmtDbContext dbContext,
        ILogger<ConfirmEmailChangeHandler> logger) : IConfirmEmailChangeHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(
            ConfirmEmailChangeRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Canonical lookup by current email — IdmtUser is global post-Phase 1.
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user is null)
                {
                    return IdmtErrors.Email.ConfirmationFailed;
                }

                // Verify there is a pending email change matching the requested NewEmail.
                if (string.IsNullOrEmpty(user.PendingEmail))
                {
                    return IdmtErrors.Email.NoPendingChange;
                }

                if (!string.Equals(user.PendingEmail, request.NewEmail, StringComparison.OrdinalIgnoreCase))
                {
                    return IdmtErrors.Email.PendingMismatch;
                }

                // ChangeEmailAsync atomically validates the token, updates Email + NormalizedEmail,
                // sets EmailConfirmed = true, and rotates the SecurityStamp. Token bound to
                // (user.Id, post-staging SecurityStamp, "ChangeEmail:newEmail" purpose).
                var changeResult = await userManager.ChangeEmailAsync(user, request.NewEmail, request.Token);
                if (!changeResult.Succeeded)
                {
                    logger.LogWarning(
                        "ChangeEmailAsync failed for {Email}: {Errors}",
                        PiiMasker.MaskEmail(request.Email),
                        string.Join(", ", changeResult.Errors.Select(e => e.Description)));
                    return IdmtErrors.Email.ConfirmationFailed;
                }

                // Clear staging slot. Reload first to pick up post-rotation stamp from
                // ChangeEmailAsync, then null out PendingEmail and persist.
                await dbContext.Entry(user).ReloadAsync(cancellationToken);
                user.PendingEmail = null;
                await dbContext.SaveChangesAsync(cancellationToken);

                logger.LogInformation(
                    "Email change confirmed. User: {UserId}.",
                    user.Id);

                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error confirming email change for {Email}", PiiMasker.MaskEmail(request.Email));
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    /// <summary>
    /// Endpoint mapping for POST /auth/confirm-email-change.
    /// MS-5 decision: AllowAnonymous — the change-email token itself binds the user
    /// (id + security stamp + new-email purpose) and is single-use. Forcing auth on a
    /// link clicked from email is poor UX and adds no security: a stolen token alone
    /// is sufficient to confirm regardless of session state.
    /// </summary>
    public static RouteHandlerBuilder MapConfirmEmailChangeEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/confirm-email-change", async Task<Results<Ok, ValidationProblem, BadRequest, InternalServerError>> (
            [FromBody] ConfirmEmailChangeRequest request,
            [FromServices] IConfirmEmailChangeHandler handler,
            [FromServices] IValidator<ConfirmEmailChangeRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            // Decode Base64URL-encoded token (matches /auth/confirm-email and /auth/reset-password).
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
                return result.FirstError.Type switch
                {
                    ErrorType.Validation => TypedResults.BadRequest(),
                    ErrorType.Failure => TypedResults.BadRequest(),
                    ErrorType.NotFound => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }

            return TypedResults.Ok();
        })
        .WithSummary("Confirm email change")
        .WithDescription("Confirms an out-of-band email change previously staged via PUT /manage/info.")
        .AllowAnonymous();
    }
}
