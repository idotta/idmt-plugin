namespace Idmt.Plugin.Features.Login;

public interface ILoginHandler
{
    Task<LoginResponse> HandleAsync(
        LoginRequest loginRequest,
        bool useCookies,
        bool useSessionCookies,
        CancellationToken cancellationToken = default);
}
