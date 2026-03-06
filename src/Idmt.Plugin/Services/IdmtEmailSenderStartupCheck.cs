using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

/// <summary>
/// A startup check that logs a warning when <see cref="IdmtEmailSender"/> (the built-in no-op
/// stub) is the registered <see cref="IEmailSender{IdmtUser}"/> implementation. This surfaces
/// the misconfiguration at application startup rather than silently at the point where an email
/// would have been delivered.
/// </summary>
/// <remarks>
/// To silence this warning, register a real <c>IEmailSender&lt;IdmtUser&gt;</c> implementation
/// before calling <c>AddIdmt</c>, or replace the stub after the call:
/// <code>
/// services.AddTransient&lt;IEmailSender&lt;IdmtUser&gt;, MySmtpEmailSender&gt;();
/// </code>
/// The last registration wins because ASP.NET Core DI resolves the last-registered descriptor
/// for a given service type.
/// </remarks>
internal sealed class IdmtEmailSenderStartupCheck(
    IServiceProvider serviceProvider,
    ILogger<IdmtEmailSenderStartupCheck> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Resolve inside a scope so we do not keep scoped/transient instances alive for the
        // lifetime of the host. IEmailSender<IdmtUser> is registered as transient.
        using var scope = serviceProvider.CreateScope();
        var sender = scope.ServiceProvider.GetRequiredService<IEmailSender<IdmtUser>>();

        if (sender is IdmtEmailSender)
        {
            logger.LogWarning(
                "Using default IdmtEmailSender stub — emails will not be delivered. " +
                "Register a custom IEmailSender<IdmtUser> for production use.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
