using Idmt.Plugin.Features.Register;

namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Interface for user registration operations
/// </summary>
public interface IRegisterHandler
{
    /// <summary>
    /// Handles user registration
    /// </summary>
    /// <param name="request">Registration request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration response</returns>
    Task<RegisterResponse> HandleAsync(RegisterRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Confirms user email address
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Confirmation token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if confirmation was successful</returns>
    Task<bool> ConfirmEmailAsync(string userId, string token, CancellationToken cancellationToken);
}