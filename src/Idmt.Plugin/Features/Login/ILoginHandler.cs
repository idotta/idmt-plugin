namespace Idmt.Plugin.Features.Login;

/// <summary>
/// Interface for login operations
/// </summary>
public interface ILoginHandler
{
    /// <summary>
    /// Handles user login
    /// </summary>
    /// <param name="loginRequest">The login request</param>
    /// <param name="useCookies">Whether to use cookie-based authentication instead of bearer tokens</param>
    /// <param name="useSessionCookies">Whether to use session cookies instead of persistent cookies</param>
    /// <param name="cancellationToken">The cancellation token</param>
    /// <returns>Login response</returns>
    Task<LoginResponse> HandleAsync(
        LoginRequest loginRequest,
        bool useCookies,
        bool useSessionCookies,
        CancellationToken cancellationToken = default);
}