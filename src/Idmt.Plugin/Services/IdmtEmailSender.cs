using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

public class IdmtEmailSender(ILogger<IdmtEmailSender> logger) : IEmailSender<IdmtUser>
{
    public virtual Task SendConfirmationLinkAsync(IdmtUser user, string email, string confirmationLink)
    {
        Console.WriteLine("Sending confirmation link to {0} with link {1}", email, confirmationLink);
        logger.LogInformation("Sending confirmation link to {Email} with link {Link}", email, confirmationLink);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetCodeAsync(IdmtUser user, string email, string resetCode)
    {
        Console.WriteLine("Sending password reset code to {0} with code {1}", email, resetCode);
        logger.LogInformation("Sending password reset code to {Email} with code {Code}", email, resetCode);
        return Task.CompletedTask;
    }

    public virtual Task SendPasswordResetLinkAsync(IdmtUser user, string email, string resetLink)
    {
        Console.WriteLine("Sending password reset link to {0} with link {1}", email, resetLink);
        logger.LogInformation("Sending password reset link to {Email} with link {Link}", email, resetLink);
        return Task.CompletedTask;
    }
}
