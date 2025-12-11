using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Middleware;

/// <summary>
/// Middleware for setting current user.
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