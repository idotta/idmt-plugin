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

    public interface IUpdateUserInfoHandler
    {
        Task<ErrorOr<Success>> HandleAsync(UpdateUserInfoRequest request, ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserInfoHandler(
        UserManager<IdmtUser> userManager,
        IdmtDbContext dbContext,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender,
        ILogger<UpdateUserInfoHandler> logger) : IUpdateUserInfoHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(
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
                bool hasChanges = false;

                // Update username if provided
                if (!string.IsNullOrWhiteSpace(request.NewUsername) && request.NewUsername != appUser.UserName)
                {
                    var setUsernameResult = await userManager.SetUserNameAsync(appUser, request.NewUsername);
                    if (!setUsernameResult.Succeeded)
                    {
                        logger.LogError("Failed to set username: {ErrorMessage}", setUsernameResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.User.UpdateFailed;
                    }
                    hasChanges = true;
                }

                // Update email if provided.
                // ChangeEmailAsync persists the new email and sets EmailConfirmed = false internally.
                // After that we send a confirmation email to the new address so the user has a
                // recovery path and is not permanently locked out.
                if (!string.IsNullOrWhiteSpace(request.NewEmail) && request.NewEmail != appUser.Email)
                {
                    var token = await userManager.GenerateChangeEmailTokenAsync(appUser, request.NewEmail);
                    var changeEmailResult = await userManager.ChangeEmailAsync(appUser, request.NewEmail, token);
                    if (!changeEmailResult.Succeeded)
                    {
                        logger.LogError("Failed to change email: {ErrorMessage}", changeEmailResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.User.UpdateFailed;
                    }

                    // ChangeEmailAsync already persisted EmailConfirmed = false — do NOT set it again
                    // or call UpdateAsync for the email change; doing so is redundant and can cause
                    // a second write with a stale concurrency stamp.

                    // Generate a fresh confirmation token (the change-email token above is now consumed)
                    // and send the link to the new address so the user can re-confirm.
                    var confirmToken = await userManager.GenerateEmailConfirmationTokenAsync(appUser);
                    var confirmLink = linkGenerator.GenerateConfirmEmailLink(request.NewEmail, confirmToken);
                    await emailSender.SendConfirmationLinkAsync(appUser, request.NewEmail, confirmLink);

                    logger.LogInformation("Email changed for user. Confirmation email dispatched to new address.");
                    // hasChanges intentionally not set here: ChangeEmailAsync already persisted the
                    // email change. The flag only controls the final UpdateAsync for other field
                    // changes (username, password) that are still pending.
                }

                // Update password if provided
                if (!string.IsNullOrWhiteSpace(request.OldPassword) && !string.IsNullOrWhiteSpace(request.NewPassword))
                {
                    var changePasswordResult = await userManager.ChangePasswordAsync(appUser, request.OldPassword, request.NewPassword);
                    if (!changePasswordResult.Succeeded)
                    {
                        logger.LogError("Failed to change password: {ErrorMessage}", changePasswordResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.Password.ResetFailed;
                    }
                    hasChanges = true;
                }

                if (hasChanges)
                {
                    var updateResult = await userManager.UpdateAsync(appUser);
                    if (!updateResult.Succeeded)
                    {
                        logger.LogError("Failed to update user: {Errors}", string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                        await transaction.RollbackAsync(cancellationToken);
                        return IdmtErrors.User.UpdateFailed;
                    }
                }

                await transaction.CommitAsync(cancellationToken);

                return Result.Success;
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
        return endpoints.MapPut("/info", async Task<Results<Ok, ValidationProblem, BadRequest, NotFound, ForbidHttpResult, InternalServerError>> (
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
                    ErrorType.Validation => TypedResults.BadRequest(),
                    ErrorType.Failure => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .WithSummary("Update user info")
        .WithDescription("Update current user authentication info")
        .RequireAuthorization();
    }
}
