using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

public class IdmtEmailSender(ILogger<IdmtEmailSender> logger) : IEmailSender<IdmtUser>
{
    public virtual Task SendConfirmationLinkAsync(IdmtUser user, string email, string confirmationLink)
    {
        logger.LogInformation("Sending confirmation link to {Email} with link {Link}", email, confirmationLink);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetCodeAsync(IdmtUser user, string email, string resetCode)
    {
        logger.LogInformation("Sending password reset code to {Email} with code {Code}", email, resetCode);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetLinkAsync(IdmtUser user, string email, string resetLink)
    {
        logger.LogInformation("Sending password reset link to {Email} with link {Link}", email, resetLink);
        return Task.CompletedTask;
    }
}
