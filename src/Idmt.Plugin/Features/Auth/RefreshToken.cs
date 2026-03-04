using System.Security.Claims;
using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
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
        Task<ErrorOr<RefreshTokenResponse>> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class RefreshTokenHandler(
        IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
        TimeProvider timeProvider,
        SignInManager<IdmtUser> signInManager,
        IMultiTenantContextAccessor<IdmtTenantInfo> tenantContextAccessor,
        IOptions<IdmtOptions> idmtOptions)
        : IRefreshTokenHandler
    {
        public async Task<ErrorOr<RefreshTokenResponse>> HandleAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            var refreshTokenProtector = bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
            var refreshTicket = refreshTokenProtector.Unprotect(request.RefreshToken);

            if (refreshTicket?.Properties?.ExpiresUtc is not { } expiresUtc ||
                timeProvider.GetUtcNow() >= expiresUtc ||
                await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not IdmtUser user)
            {
                return IdmtErrors.Token.Invalid;
            }

            if (!user.IsActive)
            {
                return IdmtErrors.Auth.Unauthorized;
            }

            // Validate tenant context matches refresh token
            var tenantClaimKey = idmtOptions.Value.MultiTenant.StrategyOptions.GetValueOrDefault(
                IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);
            var tokenTenantClaim = refreshTicket.Principal?.FindFirst(tenantClaimKey)?.Value;
            var currentTenant = tenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier;

            if (tokenTenantClaim is null || currentTenant is null || tokenTenantClaim != currentTenant)
            {
                return IdmtErrors.Auth.Unauthorized;
            }

            ClaimsPrincipal claimsPrincipal = await signInManager.CreateUserPrincipalAsync(user);
            return new RefreshTokenResponse(claimsPrincipal);
        }
    }

    public static RouteHandlerBuilder MapRefreshTokenEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/refresh", async Task<Results<SignInHttpResult, ChallengeHttpResult, ValidationProblem>> (
            [FromBody] RefreshTokenRequest request,
            [FromServices] IRefreshTokenHandler handler,
            [FromServices] IValidator<RefreshTokenRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (response.IsError)
            {
                return TypedResults.Challenge();
            }
            return TypedResults.SignIn(response.Value.ClaimsPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
        })
        .WithSummary("Refresh token")
        .WithDescription("Refresh JWT token using refresh token");
    }
}
