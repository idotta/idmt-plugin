using System.Text;
using System.Text.Encodings.Web;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;

namespace Idmt.Plugin.Services;

/// <summary>
/// IDMT email service.
/// </summary>
public sealed class IdmtEmailService(IHttpContextAccessor httpContextAccessor,
    IEmailSender<IdmtUser> emailSender,
    LinkGenerator linkGenerator,
    IMultiTenantContextAccessor multiTenantContextAccessor)
{
    public async Task SendConfirmationEmailAsync(IdmtUser user, UserManager<IdmtUser> userManager, string email)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }
        if (string.IsNullOrEmpty(ApplicationOptions.ConfirmEmailEndpointName))
        {
            throw new NotSupportedException("No email confirmation endpoint was registered!");
        }
        if (string.IsNullOrEmpty(email))
        {
            throw new InvalidOperationException("The user does not have an email address.");
        }

        string token = await userManager.GenerateEmailConfirmationTokenAsync(user);

        var routeValues = new RouteValueDictionary()
        {
            ["tenantId"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id,
            ["email"] = email,
            ["token"] = token,
        };

        var confirmEmailUrl = linkGenerator.GetUriByName(httpContextAccessor.HttpContext, ApplicationOptions.ConfirmEmailEndpointName, routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.ConfirmEmailEndpointName}'.");

        await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
    }

    public async Task SendConfirmationEmailChangeAsync(IdmtUser user, UserManager<IdmtUser> userManager, string email)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }
        if (string.IsNullOrEmpty(user.Email))
        {
            throw new InvalidOperationException("The user does not have an email address.");
        }

        var code = await userManager.GenerateChangeEmailTokenAsync(user, email);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var userId = await userManager.GetUserIdAsync(user);
        var routeValues = new RouteValueDictionary()
        {
            ["tenantId"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id,
            ["userId"] = userId,
            ["code"] = code,
            ["changedEmail"] = email,
        };

        var confirmEmailUrl = linkGenerator.GetUriByName(httpContextAccessor.HttpContext, ApplicationOptions.ConfirmEmailEndpointName, routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.ConfirmEmailEndpointName}'.");

        await emailSender.SendConfirmationLinkAsync(user, user.Email, HtmlEncoder.Default.Encode(confirmEmailUrl));
    }
}