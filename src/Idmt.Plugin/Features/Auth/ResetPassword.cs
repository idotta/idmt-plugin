using System.ComponentModel.DataAnnotations;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Features.Auth;

public static class ResetPassword
{
    public sealed record ResetPasswordRequest(string Email, string Token, string NewPassword);

    public sealed record ResetPasswordResponse(bool Success, string? Message = null);

    public interface IResetPasswordHandler
    {
        Task<ResetPasswordResponse> HandleAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResetPasswordHandler(
        UserManager<IdmtUser> userManager
        ) : IResetPasswordHandler
    {
        public async Task<ResetPasswordResponse> HandleAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new ResetPasswordResponse(false, "User not found");
            }

            // Reset password using the token
            var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ResetPasswordResponse(false, errors);
            }

            if (!user.EmailConfirmed)
            {
                user.EmailConfirmed = true;
                await userManager.UpdateAsync(user);
            }

            return new ResetPasswordResponse(true, "Password reset successfully");
        }
    }

    public static Dictionary<string, string[]>? Validate(this ResetPasswordRequest request, Configuration.PasswordOptions options)
    {
        var errors = new Dictionary<string, string[]>();
        if (!Validators.IsValidEmail(request.Email))
        {
            errors["Email"] = ["Invalid email address."];
        }
        if (string.IsNullOrEmpty(request.Token))
        {
            errors["Token"] = ["Token is required"];
        }
        if (!Validators.IsValidNewPassword(request.NewPassword, options, out var newPasswordErrors))
        {
            errors["NewPassword"] = newPasswordErrors ?? [];
        }

        return errors.Count == 0 ? null : errors;
    }
}