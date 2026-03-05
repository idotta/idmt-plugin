using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

public class IdmtEmailSender(ILogger<IdmtEmailSender> logger) : IEmailSender<IdmtUser>
{
    public virtual Task SendConfirmationLinkAsync(IdmtUser user, string email, string confirmationLink)
    {
        logger.LogWarning("Email sending is not configured (stub implementation). Confirmation link for {Email} was not sent", email);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetCodeAsync(IdmtUser user, string email, string resetCode)
    {
        logger.LogWarning("Email sending is not configured (stub implementation). Password reset code for {Email} was not sent", email);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetLinkAsync(IdmtUser user, string email, string resetLink)
    {
        logger.LogWarning("Email sending is not configured (stub implementation). Password reset link for {Email} was not sent", email);
        return Task.CompletedTask;
    }
}
