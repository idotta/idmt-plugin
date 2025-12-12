using System.Text.Encodings.Web;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;


namespace Idmt.Plugin.Services;

/// <summary>
/// IDMT email service.
/// </summary>
public sealed class IdmtEmailService(
    IEmailSender<IdmtUser> emailSender,
    IdmtLinkGenerator linkGenerator)
{
    public async Task<(string token, string confirmationUrl)> SendConfirmationEmailAsync(IdmtUser user, UserManager<IdmtUser> userManager, string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            throw new InvalidOperationException("The user does not have an email address.");
        }

        string token = await userManager.GenerateEmailConfirmationTokenAsync(user);

        string confirmEmailUrl = linkGenerator.GenerateConfirmEmailLink(email, token);

        await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));

        return (token, confirmEmailUrl);
    }
}