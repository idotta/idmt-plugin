namespace Idmt.Plugin.Features.Logout;

internal sealed class LogoutHandler : ILogoutHandler
{
    public async Task<LogoutResponse> HandleAsync(LogoutRequest request, string? userId = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return new LogoutResponse
            {
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