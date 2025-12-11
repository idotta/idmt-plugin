using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Features.Auth;

public static class ConfirmEmail
{
    public sealed record ConfirmEmailRequest(string Email, string Token);

    public sealed record ConfirmEmailResponse(bool Success, string? Message = null);

    public interface IConfirmEmailHandler
    {
        Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ConfirmEmailHandler(UserManager<IdmtUser> userManager) : IConfirmEmailHandler
    {
        public async Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new ConfirmEmailResponse(false, "Confirmation failed");
            }

            if (user.EmailConfirmed)
            {
                return new ConfirmEmailResponse(true, "Email already confirmed");
            }

            var result = await userManager.ConfirmEmailAsync(user, request.Token);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ConfirmEmailResponse(false, errors);
            }

            return new ConfirmEmailResponse(true, "Email confirmed successfully");
        }
    }

    public static Dictionary<string, string[]>? Validate(this ConfirmEmailRequest request)
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

        return errors.Count == 0 ? null : errors;
    }
}
