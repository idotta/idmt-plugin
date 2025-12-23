using Idmt.Plugin.Features.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var auth = endpoints.MapGroup("/auth")
            .WithTags("Authentication");

        auth.MapCookieLoginEndpoint();
        auth.MapLogoutEndpoint();
        auth.MapTokenLoginEndpoint();
        auth.MapRefreshTokenEndpoint();
        auth.MapConfirmEmailEndpoint();
        auth.MapResendConfirmationEmailEndpoint();
        auth.MapForgotPasswordEndpoint();
        auth.MapResetPasswordEndpoint();
        auth.MapResetPasswordRedirectEndpoint();
    }
}