namespace Idmt.Plugin.Features.Logout;

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