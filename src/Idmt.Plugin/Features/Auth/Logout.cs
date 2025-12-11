using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class Logout
{

    /// <summary>
    /// Interface for logout operations
    /// </summary>
    public interface ILogoutHandler
    {
        /// <summary>
        /// Handles user logout
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        Task HandleAsync(CancellationToken cancellationToken = default);
    }

    internal sealed class LogoutHandler(ILogger<LogoutHandler> logger, SignInManager<IdmtUser> signInManager)
    : ILogoutHandler
    {
        public async Task HandleAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await signInManager.SignOutAsync();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during logout");
                throw;
            }
        }
    }
}