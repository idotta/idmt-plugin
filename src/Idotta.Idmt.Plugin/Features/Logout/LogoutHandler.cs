using Microsoft.AspNetCore.Identity;
using Idotta.Idmt.Plugin.Models;

namespace Idotta.Idmt.Plugin.Features.Logout;

/// <summary>
/// Handler for logout operations
/// </summary>
public class LogoutHandler
{
    private readonly SignInManager<IdmtUser> _signInManager;
    private readonly UserManager<IdmtUser> _userManager;

    public LogoutHandler(
        SignInManager<IdmtUser> signInManager,
        UserManager<IdmtUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    /// <summary>
    /// Handles user logout
    /// </summary>
    /// <param name="request">Logout request</param>
    /// <param name="userId">Current user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Logout response</returns>
    public async Task<LogoutResponse> HandleAsync(LogoutRequest request, string? userId = null, CancellationToken cancellationToken = default)
    {
        try
        {
            // Sign out from current session
            await _signInManager.SignOutAsync();

            // If signout everywhere is requested and we have a user ID
            if (request.SignOutEverywhere && !string.IsNullOrEmpty(userId))
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    // Update security stamp to invalidate all existing tokens
                    await _userManager.UpdateSecurityStampAsync(user);
                }
            }

            // TODO: Implement refresh token invalidation logic
            // This would typically involve checking the refresh token against a store
            // and marking it as revoked/invalid

            return new LogoutResponse
            {
                Success = true,
                Message = "Logged out successfully"
            };
        }
        catch (Exception ex)
        {
            return new LogoutResponse
            {
                Success = false,
                ErrorMessage = "An error occurred during logout: " + ex.Message
            };
        }
    }
}