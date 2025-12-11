using System.Security.Claims;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class RefreshToken
{
    public sealed record RefreshTokenRequest(string RefreshToken);

    public sealed record RefreshTokenResponse(bool Succeeded, ClaimsPrincipal? ClaimsPrincipal = null);

    public interface IRefreshTokenHandler
    {
        Task<RefreshTokenResponse> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class RefreshTokenHandler(
        IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
        TimeProvider timeProvider,
        SignInManager<IdmtUser> signInManager)
        : IRefreshTokenHandler
    {
        public async Task<RefreshTokenResponse> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            var refreshTokenProtector = bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
            var refreshTicket = refreshTokenProtector.Unprotect(request.RefreshToken);

            if (refreshTicket?.Properties?.ExpiresUtc is not { } expiresUtc ||
                timeProvider.GetUtcNow() >= expiresUtc ||
                await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not IdmtUser user)
            {
                return new RefreshTokenResponse(false);
            }

            ClaimsPrincipal claimsPrincipal = await signInManager.CreateUserPrincipalAsync(user);
            return new RefreshTokenResponse(true, claimsPrincipal);
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
}