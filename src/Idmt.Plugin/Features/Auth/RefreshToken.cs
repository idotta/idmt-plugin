using System.Security.Claims;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class RefreshToken
{
    public sealed record RefreshTokenRequest(string RefreshToken);

    public sealed record RefreshTokenResponse(ClaimsPrincipal ClaimsPrincipal);

    public interface IRefreshTokenHandler
    {
        Task<Result<RefreshTokenResponse>> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class RefreshTokenHandler(
        IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
        TimeProvider timeProvider,
        SignInManager<IdmtUser> signInManager)
        : IRefreshTokenHandler
    {
        public async Task<Result<RefreshTokenResponse>> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            var refreshTokenProtector = bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
            var refreshTicket = refreshTokenProtector.Unprotect(request.RefreshToken);

            if (refreshTicket?.Properties?.ExpiresUtc is not { } expiresUtc ||
                timeProvider.GetUtcNow() >= expiresUtc ||
                await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not IdmtUser user)
            {
                return Result.Failure<RefreshTokenResponse>("Invalid refresh token", StatusCodes.Status400BadRequest);
            }

            ClaimsPrincipal claimsPrincipal = await signInManager.CreateUserPrincipalAsync(user);
            return Result.Success(new RefreshTokenResponse(claimsPrincipal));
        }
    }

    public static Dictionary<string, string[]>? Validate(this RefreshTokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return new Dictionary<string, string[]>
            {
                ["RefreshToken"] = ["Refresh token is required."]
            };
        }
        return null;
    }

    public static RouteHandlerBuilder MapRefreshTokenEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/refresh", async Task<Results<Ok<AccessTokenResponse>, SignInHttpResult, ChallengeHttpResult, ValidationProblem>> (
            [FromBody] RefreshTokenRequest request,
            [FromServices] IRefreshTokenHandler handler,
            HttpContext context) =>
        {
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (!response.IsSuccess)
            {
                return TypedResults.Challenge();
            }
            return TypedResults.SignIn(response.Value!.ClaimsPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
        })
        .WithSummary("Refresh token")
        .WithDescription("Refresh JWT token using refresh token")
        .RequireAuthorization();
    }
}