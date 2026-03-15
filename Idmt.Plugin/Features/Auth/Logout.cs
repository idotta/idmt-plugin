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
using Microsoft.Extensions.DependencyInjection;
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
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
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
                        // (e.g. header or route strategies at logout time). Extract the tenant
                        // identifier from the bearer principal's claims and resolve the tenant
                        // via the store so revocation can still proceed.
                        var tenantClaimKey = idmtOptions.Value.MultiTenant.StrategyOptions
                            .GetValueOrDefault(IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);
                        var tenantIdentifierFromClaim = currentUserService.User?.FindFirst(tenantClaimKey)?.Value;

                        if (tenantIdentifierFromClaim is not null)
                        {
                            var resolvedTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifierFromClaim);
                            if (resolvedTenant?.Id is not null)
                            {
                                await tokenRevocationService.RevokeUserTokensAsync(userId, resolvedTenant.Id, cancellationToken);
                            }
                            else
                            {
                                logger.LogWarning(
                                    "Token revocation skipped for user {UserId}: tenant identifier {TenantIdentifier} from bearer claims could not be resolved.",
                                    userId, tenantIdentifierFromClaim);
                            }
                        }
                        else
                        {
                            logger.LogWarning(
                                "Token revocation skipped for user {UserId}: no tenant context resolved and no tenant claim present in bearer token.",
                                userId);
                        }
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