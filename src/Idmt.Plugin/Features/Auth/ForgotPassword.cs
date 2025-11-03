using System.Text.Encodings.Web;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Auth;

public static class ForgotPassword
{
    public sealed record ForgotPasswordRequest(string Email);

    public sealed record ForgotPasswordResponse(bool Success, string? ResetToken = null, string? ResetUrl = null, string? Message = null);

    public interface IForgotPasswordHandler
    {
        Task<ForgotPasswordResponse> HandleAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default);
    }

    public sealed class ForgotPasswordHandler(
        UserManager<IdmtUser> userManager,
        IEmailSender<IdmtUser> emailSender,
        LinkGenerator linkGenerator,
        IHttpContextAccessor httpContextAccessor,
        ICurrentUserService currentUserService) : IForgotPasswordHandler
    {
        public async Task<ForgotPasswordResponse> HandleAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.IsActive)
            {
                // Don't reveal whether user exists or not for security
                return new ForgotPasswordResponse(true, Message: "If the email exists, a reset link has been sent.");
            }

            // Generate password reset token
            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            // Create reset URL if base URL is configured
            var routeValues = new RouteValueDictionary()
            {
                ["tenantId"] = currentUserService.TenantId!,
                ["email"] = user.Email,
                ["token"] = token,
            };

            var resetUrl = linkGenerator.GetUriByName(httpContextAccessor.HttpContext!, ApplicationOptions.PasswordResetEndpointName, routeValues)
                ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.PasswordResetEndpointName}'.");

            // Send email with reset code
            await emailSender.SendPasswordResetCodeAsync(user, request.Email, HtmlEncoder.Default.Encode(resetUrl));

            return new ForgotPasswordResponse(true, token, resetUrl, "If the email exists, a reset link has been sent.");
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
}
