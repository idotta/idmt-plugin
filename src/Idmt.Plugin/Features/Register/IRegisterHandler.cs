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
    Task<RegisterResponse> HandleAsync(RegisterRequest request, CancellationToken cancellationToken = default);
}