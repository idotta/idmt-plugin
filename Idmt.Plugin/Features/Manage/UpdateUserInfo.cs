using System.Security.Claims;
using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Manage;

public static class UpdateUserInfo
{
    public sealed record UpdateUserInfoRequest(
        string? OldPassword = null,
        string? NewUsername = null,
        string? NewEmail = null,
        string? NewPassword = null
    );

    /// <summary>
    /// Internal handler result. Never serialized to clients — both 200 (no email change) and 202
    /// (email change staged) responses have empty bodies. Carries only the signal needed by the
    /// endpoint mapping to choose the response status.
    /// </summary>
    internal sealed record UpdateUserInfoResult(bool EmailChangePending);

    internal interface IUpdateUserInfoHandler
    {
        Task<ErrorOr<UpdateUserInfoResult>> HandleAsync(UpdateUserInfoRequest request, ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserInfoHandler(
        UserManager<IdmtUser> userManager,
        IdmtDbContext dbContext,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender,
        ICurrentUserService currentUserService,
        ITokenRevocationService tokenRevocationService,
        ILogger<UpdateUserInfoHandler> logger) : IUpdateUserInfoHandler
    {
        public async Task<ErrorOr<UpdateUserInfoResult>> HandleAsync(
            UpdateUserInfoRequest request,
            ClaimsPrincipal user,
            CancellationToken cancellationToken = default)
        {
            var userEmail = user.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(userEmail))
            {
                return IdmtErrors.User.ClaimsNotFound;
            }

            var appUser = await userManager.FindByEmailAsync(userEmail);
            if (appUser == null)
            {
                return IdmtErrors.User.NotFound;
            }
            if (!appUser.IsActive)
            {
                return IdmtErrors.User.Inactive;
            }

            await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
            try
            {
                bool emailChangeRequested =
                    !string.IsNullOrWhiteSpace(request.NewEmail) &&
                    !string.Equals(request.NewEmail, appUser.Email, StringComparison.OrdinalIgnoreCase);
                bool usernameChanged = false;
                bool passwordChanged = false;

                // 1. Apply username change first. SetUserNameAsync rotates SecurityStamp.
                if (!string.IsNullOrWhiteSpace(request.NewUsername) && request.NewUsername != appUser.UserName)
                {
                    var setUsernameResult = await userManager.SetUserNameAsync(appUser, request.NewUsername);
                    if (!setUsernameResult.Succeeded)
                    {
                        logger.LogError("Failed to set username: {ErrorMessage}", setUsernameResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.User.UpdateFailed;
                    }
                    usernameChanged = true;
                }

                // 2. Apply password change. ChangePasswordAsync rotates SecurityStamp.
                if (!string.IsNullOrWhiteSpace(request.OldPassword) && !string.IsNullOrWhiteSpace(request.NewPassword))
                {
                    var changePasswordResult = await userManager.ChangePasswordAsync(appUser, request.OldPassword, request.NewPassword);
                    if (!changePasswordResult.Succeeded)
                    {
                        logger.LogError("Failed to change password: {ErrorMessage}", changePasswordResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.Password.ResetFailed;
                    }
                    passwordChanged = true;
                }

                // 3. Stage email change (out-of-band confirmation).
                //
                // CRITICAL invariant 5a (CD-1): GenerateChangeEmailTokenAsync must be called AFTER all
                // other stamp-rotating mutations (SetUserNameAsync / ChangePasswordAsync). The token is
                // bound to (user.Id + SecurityStamp + "ChangeEmail:newEmail" purpose). If we generated
                // it earlier, ChangePasswordAsync / SetUserNameAsync would rotate the stamp and the
                // token would fail validation at confirm time. We flush + reload here to ensure the
                // token is generated against the post-rotation stamp persisted in the database.
                if (emailChangeRequested)
                {
                    await dbContext.SaveChangesAsync(cancellationToken);
                    await dbContext.Entry(appUser).ReloadAsync(cancellationToken);

                    var token = await userManager.GenerateChangeEmailTokenAsync(appUser, request.NewEmail!);

                    // Stage the new email. Email column itself is NOT mutated — only PendingEmail.
                    appUser.PendingEmail = request.NewEmail;
                    await dbContext.SaveChangesAsync(cancellationToken);

                    var confirmLink = linkGenerator.GenerateConfirmEmailChangeLink(appUser.Email!, request.NewEmail!, token);
                    await emailSender.SendConfirmationLinkAsync(appUser, request.NewEmail!, confirmLink);

                    logger.LogInformation(
                        "Email change staged. Confirmation link dispatched to new address. User: {UserId}.",
                        appUser.Id);
                }
                else
                {
                    // No email change. Persist any pending username/password mutations.
                    await dbContext.SaveChangesAsync(cancellationToken);
                }

                // Revoke existing bearer tokens ONLY when credentials (username or password)
                // actually changed. Email-only requests do NOT revoke at staging time —
                // Identity's ChangeEmailAsync at confirm-time rotates SecurityStamp and
                // naturally invalidates sessions then.
                bool credentialsChanged = passwordChanged || usernameChanged;
                if (credentialsChanged
                    && currentUserService.UserId is { } uid
                    && currentUserService.TenantId is { } tid)
                {
                    await tokenRevocationService.RevokeUserTokensAsync(uid, tid, cancellationToken);
                }

                await transaction.CommitAsync(cancellationToken);

                return new UpdateUserInfoResult(EmailChangePending: emailChangeRequested);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync(cancellationToken);
                logger.LogError(ex, "Exception occurred during user info update. Transaction rolled back.");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapUpdateUserInfoEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPut("/info", async Task<Results<Ok, Accepted, ValidationProblem, NotFound, ForbidHttpResult, InternalServerError>> (
            [FromBody] UpdateUserInfoRequest request,
            ClaimsPrincipal user,
            [FromServices] IUpdateUserInfoHandler handler,
            [FromServices] IValidator<UpdateUserInfoRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } errors)
            {
                return TypedResults.ValidationProblem(errors);
            }

            var result = await handler.HandleAsync(request, user, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.NotFound => TypedResults.NotFound(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.Validation => TypedResults.ValidationProblem(new Dictionary<string, string[]> { [result.FirstError.Code] = [result.FirstError.Description] }),
                    ErrorType.Failure => TypedResults.ValidationProblem(new Dictionary<string, string[]> { [result.FirstError.Code] = [result.FirstError.Description] }),
                    _ => TypedResults.InternalServerError(),
                };
            }

            // 202 Accepted with empty body when email change is staged but not yet confirmed.
            // Pointing Location header at the confirm endpoint signals the next step.
            if (result.Value.EmailChangePending)
            {
                return TypedResults.Accepted("/auth/confirm-email-change");
            }
            return TypedResults.Ok();
        })
        .WithSummary("Update user info")
        .WithDescription("Update current user authentication info. Email changes are staged out-of-band; a confirmation link is sent to the new address and the email is committed only when the user confirms via /auth/confirm-email-change.")
        .RequireAuthorization();
    }
}
