using System.Security.Claims;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
        Task<bool> HandleAsync(UpdateUserInfoRequest request, ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class UpdateUserInfoHandler(
        UserManager<IdmtUser> userManager,
        IdmtDbContext dbContext,
        ILogger<UpdateUserInfoHandler> logger) : IUpdateUserInfoHandler
    {
        public async Task<bool> HandleAsync(
            UpdateUserInfoRequest request,
            ClaimsPrincipal user,
            CancellationToken cancellationToken = default)
        {
            var userEmail = user.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(userEmail))
            {
                return false;
            }

            var appUser = await userManager.FindByEmailAsync(userEmail);
            if (appUser == null || !appUser.IsActive)
            {
                return false;
            }

            await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
            try
            {
                // Update username if provided
                if (!string.IsNullOrWhiteSpace(request.NewUsername) && request.NewUsername != appUser.UserName)
                {
                    var setUsernameResult = await userManager.SetUserNameAsync(appUser, request.NewUsername);
                    if (!setUsernameResult.Succeeded)
                    {
                        logger.LogError("Failed to set username: {ErrorMessage}", setUsernameResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }
                }

                // Update email if provided
                if (!string.IsNullOrWhiteSpace(request.NewEmail) && request.NewEmail != appUser.Email)
                {
                    // Generate email change token
                    var token = await userManager.GenerateChangeEmailTokenAsync(appUser, request.NewEmail);
                    var result = await userManager.ChangeEmailAsync(appUser, request.NewEmail, token);
                    appUser.EmailConfirmed = false;
                    await userManager.UpdateAsync(appUser);

                    if (!result.Succeeded)
                    {
                        logger.LogError("Failed to change email: {ErrorMessage}", result.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }
                }

                // Update password if provided
                if (!string.IsNullOrEmpty(request.OldPassword) && !string.IsNullOrWhiteSpace(request.NewPassword))
                {
                    var changePasswordResult = await userManager.ChangePasswordAsync(appUser, request.OldPassword, request.NewPassword);
                    if (!changePasswordResult.Succeeded)
                    {
                        logger.LogError("Failed to change password: {ErrorMessage}", changePasswordResult.Errors.Select(e => e.Description));
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }
                }

                await userManager.UpdateAsync(appUser);

                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync(cancellationToken);
                logger.LogError(ex, "Exception occurred during user registration. Transaction rolled back.");
                throw;
            }
            return true;
        }
    }

    public static Dictionary<string, string[]>? Validate(this UpdateUserInfoRequest request, Configuration.PasswordOptions options)
    {
        var errors = new Dictionary<string, string[]>();
        // Only require old password when NewPassword is provided
        if (!string.IsNullOrEmpty(request.NewPassword) && string.IsNullOrEmpty(request.OldPassword))
        {
            errors["OldPassword"] = ["Old password is required to change password"];
        }
        if (request.NewEmail is not null && !Validators.IsValidEmail(request.NewEmail))
        {
            errors["NewEmail"] = ["New email is not valid"];
        }
        if (request.NewPassword is not null && !Validators.IsValidNewPassword(request.NewPassword, options, out var newPasswordErrors))
        {
            errors["NewPassword"] = newPasswordErrors ?? [];
        }

        return errors.Count == 0 ? null : errors;
    }

    public static RouteHandlerBuilder MapUpdateUserInfoEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPut("/info", async Task<Results<Ok, ProblemHttpResult, ValidationProblem>> (
            [FromBody] UpdateUserInfoRequest request,
            ClaimsPrincipal user,
            [FromServices] IUpdateUserInfoHandler handler,
            [FromServices] IOptions<IdmtOptions> options,
            HttpContext context) =>
        {
            if (request.Validate(options.Value.Identity.Password) is { } errors)
            {
                return TypedResults.ValidationProblem(errors);
            }

            var result = await handler.HandleAsync(request, user, cancellationToken: context.RequestAborted);
            if (!result)
            {
                return TypedResults.Problem("Failed to update user info");
            }
            return TypedResults.Ok();
        })
        .WithSummary("Update user info")
        .WithDescription("Update current user authentication info");
    }
}