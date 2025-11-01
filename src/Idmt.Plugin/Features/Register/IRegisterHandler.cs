namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Handler interface for user registration operations following the vertical slice architecture pattern.
/// Implementations handle the complete registration workflow including validation, user creation,
/// role assignment, and password setup token generation.
/// </summary>
public interface IRegisterHandler
{
    /// <summary>
    /// Handles a user registration request. Creates a new user account without a password,
    /// assigns the specified role, and generates a password setup token.
    /// </summary>
    /// <param name="request">The registration request containing email, optional username, and role</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
    /// <returns>Registration response containing success status, user ID, password setup token, and any errors</returns>
    Task<RegisterUserResponse> HandleAsync(RegisterUserRequest request, CancellationToken cancellationToken = default);
}
