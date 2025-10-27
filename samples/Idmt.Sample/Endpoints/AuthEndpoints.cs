using Idmt.Plugin.Features.Login;
using Idmt.Plugin.Features.Register;
using Idmt.Plugin.Features.Logout;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Idmt.Sample.Endpoints;

/// <summary>
/// Authentication endpoints using minimal APIs
/// </summary>
public static class AuthEndpoints
{
    /// <summary>
    /// Maps authentication endpoints
    /// </summary>
    /// <param name="app">The web application</param>
    /// <returns>The route group builder</returns>
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth")
            .WithTags("Authentication")
            ;

        // Login endpoint
        group.MapPost("/login", LoginAsync)
            .WithName("Login")
            .WithSummary("Authenticates a user and returns a JWT token")
            .Produces<LoginResponse>(200)
            .Produces(400);

        // Register endpoint
        group.MapPost("/register", RegisterAsync)
            .WithName("Register")
            .WithSummary("Registers a new user account")
            .Produces<RegisterResponse>(200)
            .Produces(400);

        // Logout endpoint
        group.MapPost("/logout", LogoutAsync)
            .WithName("Logout")
            .WithSummary("Logs out the current user")
            .Produces<LogoutResponse>(200)
            .Produces(400)
            .RequireAuthorization();

        // Email confirmation endpoint
        group.MapGet("/confirm-email", ConfirmEmailAsync)
            .WithName("ConfirmEmail")
            .WithSummary("Confirms a user's email address")
            .Produces(200)
            .Produces(400);

        return group;
    }

    /// <summary>
    /// Handles user login
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <param name="loginHandler">Login handler from DI</param>
    /// <param name="useCookies">Whether to use cookie-based authentication</param>
    /// <param name="useSessionCookies">Whether to use session cookies</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication response with token</returns>
    private static async Task<IResult> LoginAsync(
        [FromBody] LoginRequest request,
        [FromServices] ILoginHandler loginHandler,
        [FromQuery] bool useCookies = false,
        [FromQuery] bool useSessionCookies = false,
        CancellationToken cancellationToken = default)
    {
        var response = await loginHandler.HandleAsync(request, useCookies, useSessionCookies, cancellationToken);
        
        if (!response.Success)
        {
            return Results.BadRequest(response);
        }

        return Results.Ok(response);
    }

    /// <summary>
    /// Handles user registration
    /// </summary>
    /// <param name="request">Registration details</param>
    /// <param name="registerHandler">Register handler from DI</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration response</returns>
    private static async Task<IResult> RegisterAsync(
        [FromBody] RegisterRequest request,
        [FromServices] IRegisterHandler registerHandler,
        CancellationToken cancellationToken = default)
    {
        var response = await registerHandler.HandleAsync(request, cancellationToken);
        
        if (!response.Success)
        {
            return Results.BadRequest(response);
        }

        return Results.Ok(response);
    }

    /// <summary>
    /// Handles user logout
    /// </summary>
    /// <param name="request">Logout request</param>
    /// <param name="logoutHandler">Logout handler from DI</param>
    /// <param name="httpContext">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Logout response</returns>
    private static async Task<IResult> LogoutAsync(
        [FromBody] LogoutRequest request,
        [FromServices] ILogoutHandler logoutHandler,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        var userId = httpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        var response = await logoutHandler.HandleAsync(request, userId, cancellationToken);
        
        if (!response.Success)
        {
            return Results.BadRequest(response);
        }

        return Results.Ok(response);
    }

    /// <summary>
    /// Confirms a user's email address
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Confirmation token</param>
    /// <param name="registerHandler">Register handler from DI</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Confirmation result</returns>
    private static async Task<IResult> ConfirmEmailAsync(
        [FromQuery] string userId,
        [FromQuery] string token,
        [FromServices] IRegisterHandler registerHandler,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            return Results.BadRequest(new { error = "User ID and token are required" });
        }

        var success = await registerHandler.ConfirmEmailAsync(userId, token, cancellationToken);
        
        if (!success)
        {
            return Results.BadRequest(new { error = "Email confirmation failed" });
        }

        return Results.Ok(new { message = "Email confirmed successfully" });
    }
}