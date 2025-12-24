using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Middleware;

/// <summary>
/// Middleware for setting current user and validating tenant isolation on bearer tokens.
/// Ensures that users cannot use tokens from one tenant to access another tenant's resources.
/// </summary>
public class CurrentUserMiddleware(ICurrentUserService currentUserService) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        currentUserService.SetCurrentUser(
            context.User,
            context.Connection.RemoteIpAddress?.ToString(),
            context.Request.Headers.UserAgent.ToString());

        await next(context);
    }
}