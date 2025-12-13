using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Plugin.Features.Auth;

public static class ResetPassword
{
    public sealed record ResetPasswordRequest(string NewPassword);

    public sealed record ResetPasswordResponse(bool Success, string[]? Errors = null);

    public interface IResetPasswordHandler
    {
        Task<ResetPasswordResponse> HandleAsync(string tenantId, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResetPasswordHandler(IServiceProvider sp) : IResetPasswordHandler
    {
        public async Task<ResetPasswordResponse> HandleAsync(string tenantId, string email, string token, ResetPasswordRequest request, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(tenantId))
            {
                return new ResetPasswordResponse(false, ["Tenant ID is required"]);
            }
            try
            {
                var userManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                var user = await userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return new ResetPasswordResponse(false, ["User not found"]);
                }

                // Reset password using the token
                var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return new ResetPasswordResponse(false, [errors]);
                }

                if (!user.EmailConfirmed)
                {
                    user.EmailConfirmed = true;
                    await userManager.UpdateAsync(user);
                }

                return new ResetPasswordResponse(true, null);
            }
            catch (Exception ex)
            {
                return new ResetPasswordResponse(false, [ex.Message]);
            }
        }
    }

    public static Dictionary<string, string[]>? Validate(this ResetPasswordRequest request, string tenantId, string email, string token, Configuration.PasswordOptions options)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrEmpty(tenantId))
        {
            errors["TenantId"] = ["Tenant ID is required"];
        }
        if (!Validators.IsValidEmail(email))
        {
            errors["Email"] = ["Invalid email address."];
        }
        if (string.IsNullOrEmpty(token))
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