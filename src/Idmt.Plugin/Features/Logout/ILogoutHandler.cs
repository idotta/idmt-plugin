namespace Idmt.Plugin.Features.Logout;

/// <summary>
/// Interface for logout operations
/// </summary>
public interface ILogoutHandler
{
    /// <summary>
    /// Handles user logout
    /// </summary>
    /// <param name="request">Logout request</param>
    /// <param name="userId">Current user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Logout response</returns>
    Task<LogoutResponse> HandleAsync(LogoutRequest request, string? userId, CancellationToken cancellationToken = default);
}