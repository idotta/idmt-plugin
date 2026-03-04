using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

public class IdmtEmailSender(ILogger<IdmtEmailSender> logger) : IEmailSender<IdmtUser>
{
    public virtual Task SendConfirmationLinkAsync(IdmtUser user, string email, string confirmationLink)
    {
        logger.LogDebug("Confirmation link generated for {Email}", email);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetCodeAsync(IdmtUser user, string email, string resetCode)
    {
        logger.LogDebug("Password reset code generated for {Email}", email);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetLinkAsync(IdmtUser user, string email, string resetLink)
    {
        logger.LogDebug("Password reset link generated for {Email}", email);
        return Task.CompletedTask;
    }
}
