using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class Logout
{
    public interface ILogoutHandler
    {
        Task<ErrorOr<Success>> HandleAsync(CancellationToken cancellationToken = default);
    }

    internal sealed class LogoutHandler(
        ILogger<LogoutHandler> logger,
        SignInManager<IdmtUser> signInManager,
        ICurrentUserService currentUserService,
        IMultiTenantContextAccessor<IdmtTenantInfo> tenantContextAccessor,
        IOptions<IdmtOptions> idmtOptions,
        ITokenRevocationService tokenRevocationService)
        : ILogoutHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (currentUserService.UserId is { } userId)
                {
                    // Primary resolution: use the Finbuckle multi-tenant context, which provides
                    // the database Id required by the token revocation store.
                    var tenantId = tenantContextAccessor.MultiTenantContext?.TenantInfo?.Id;

                    if (tenantId is not null)
                    {
                        await tokenRevocationService.RevokeUserTokensAsync(userId, tenantId, cancellationToken);
                    }
                    else
                    {
                        // Fallback: the multi-tenant strategy did not resolve a tenant context
                        // (e.g. header or route strategies at logout time). Read the tenant claim
                        // from the bearer principal to produce a meaningful diagnostic. Token
                        // revocation cannot proceed without the tenant DB Id, so log a warning
                        // rather than silently succeeding with an unrevoked token.
                        var tenantClaimKey = idmtOptions.Value.MultiTenant.StrategyOptions
                            .GetValueOrDefault(IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);
                        var tenantIdentifierFromClaim = currentUserService.User?.FindFirst(tenantClaimKey)?.Value;

                        logger.LogWarning(
                            "Token revocation skipped for user {UserId}: tenant context could not be resolved. " +
                            "Tenant identifier from bearer claims: {TenantIdentifier}. " +
                            "Ensure the multi-tenant strategy resolves during logout requests, " +
                            "or add the claim strategy so the tenant can be resolved from the bearer token.",
                            userId,
                            tenantIdentifierFromClaim ?? "<not present in claims>");
                    }
                }

                await signInManager.SignOutAsync();
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during logout");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapLogoutEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/logout", async Task<Results<NoContent, ProblemHttpResult>> (
            [FromServices] ILogoutHandler logoutHandler,
            CancellationToken cancellationToken = default) =>
        {
            var result = await logoutHandler.HandleAsync(cancellationToken);
            if (result.IsError)
            {
                return TypedResults.Problem(result.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError);
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization()
        .WithSummary("Logout user")
        .WithDescription("Logout user and invalidate bearer token or cookie");
    }
}