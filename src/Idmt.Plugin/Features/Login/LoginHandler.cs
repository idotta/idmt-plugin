namespace Idmt.Plugin.Features.Login;

internal sealed class LoginHandler : ILoginHandler
{
    public async Task<LoginResponse> HandleAsync(
        LoginRequest loginRequest,
        bool useCookies,
        bool useSessionCookies,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return new LoginResponse
            {
            };
        }
        catch (Exception ex)
        {
            return new LoginResponse
            {
                Success = false,
                ErrorMessage = "An error occurred during login",
                Errors = [ex.Message]
            };
        }
    }
}