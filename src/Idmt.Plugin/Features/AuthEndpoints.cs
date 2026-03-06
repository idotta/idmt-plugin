using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features;

public static class AuthEndpoints
{
    /// <summary>
    /// The rate limiter policy name applied to all auth endpoints when rate limiting is enabled.
    /// </summary>
    internal const string AuthRateLimiterPolicy = "idmt-auth";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var idmtOptions = endpoints.ServiceProvider
            .GetRequiredService<IOptions<IdmtOptions>>().Value;

        var auth = endpoints.MapGroup("/auth")
            .WithTags("Authentication");

        // Apply the fixed-window rate limiter to the entire auth group to prevent
        // brute-force login attacks and email-flooding via forgot-password /
        // resend-confirmation endpoints. Only added when the feature is enabled so
        // host applications that manage their own rate limiting can opt out cleanly.
        if (idmtOptions.RateLimiting.Enabled)
        {
            auth.RequireRateLimiting(AuthRateLimiterPolicy);
        }

        auth.MapCookieLoginEndpoint();
        auth.MapLogoutEndpoint();
        auth.MapTokenLoginEndpoint();
        auth.MapRefreshTokenEndpoint();
        auth.MapConfirmEmailEndpoint();
        auth.MapConfirmEmailDirectEndpoint();
        auth.MapResendConfirmationEmailEndpoint();
        auth.MapForgotPasswordEndpoint();
        auth.MapResetPasswordEndpoint();
    }
}
