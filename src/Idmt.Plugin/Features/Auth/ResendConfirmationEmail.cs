using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Auth;

public static class ResendConfirmationEmail
{
    public sealed record ResendConfirmationEmailRequest(string Email);

    public sealed record ResendConfirmationEmailResponse(bool Success, string? ConfirmationToken = null, string? ConfirmationUrl = null, string? Message = null);

    public interface IResendConfirmationEmailHandler
    {
        Task<ResendConfirmationEmailResponse> HandleAsync(ResendConfirmationEmailRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ResendConfirmationEmailHandler(
        UserManager<IdmtUser> userManager,
        IdmtEmailService emailService
        ) : IResendConfirmationEmailHandler
    {
        public async Task<ResendConfirmationEmailResponse> HandleAsync(ResendConfirmationEmailRequest request, CancellationToken cancellationToken = default)
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

            var (token, confirmationUrl) = await emailService.SendConfirmationEmailAsync(user, userManager, request.Email);

            return new ResendConfirmationEmailResponse(true, token, confirmationUrl, "If the email exists, a confirmation link has been sent.");
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
}
