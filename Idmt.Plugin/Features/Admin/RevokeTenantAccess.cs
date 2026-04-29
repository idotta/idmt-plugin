using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class RevokeTenantAccess
{
    public interface IRevokeTenantAccessHandler
    {
        Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    // Phase 1 (canonical identity): RevokeTenantAccess flips TenantAccess.IsActive = false in a single
    // SaveChangesAsync transaction, then revokes outstanding bearer tokens by canonical UserId. No
    // shadow IdmtUser deactivation in the target tenant — IdmtUser is global post Phase 1, so there
    // is no per-tenant user row to flip. The Phase 0 self-target guard at the top of HandleAsync
    // remains in place per the architectural rule that callers cannot revoke their own access.
    internal sealed class RevokeTenantAccessHandler(
        IdmtDbContext dbContext,
        UserManager<IdmtUser> userManager,
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ITokenRevocationService tokenRevocationService,
        ICurrentUserService currentUserService,
        ILogger<RevokeTenantAccessHandler> logger) : IRevokeTenantAccessHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            if (currentUserService.UserId is null)
            {
                return IdmtErrors.Auth.Unauthorized;
            }

            if (userId == currentUserService.UserId.Value)
            {
                return IdmtErrors.General.SelfTarget;
            }

            try
            {
                // Canonical (global) IdmtUser lookup.
                var user = await userManager.FindByIdAsync(userId.ToString());
                if (user is null)
                {
                    return IdmtErrors.User.NotFound;
                }

                var targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (targetTenant is null)
                {
                    return IdmtErrors.Tenant.NotFound;
                }

                var tenantAccess = await dbContext.TenantAccess
                    .FirstOrDefaultAsync(ta => ta.UserId == user.Id && ta.TenantId == targetTenant.Id, cancellationToken);
                if (tenantAccess is null)
                {
                    return IdmtErrors.Tenant.AccessNotFound;
                }

                tenantAccess.IsActive = false;
                await dbContext.SaveChangesAsync(cancellationToken);

                // Revoke any active bearer tokens so the user cannot refresh after access is removed.
                // Token revocation keys on canonical UserId — there is no shadow user under Phase 1.
                await tokenRevocationService.RevokeUserTokensAsync(user.Id, targetTenant.Id!, cancellationToken);

                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error revoking tenant access for user {UserId} and tenant {TenantIdentifier}", userId, tenantIdentifier);
                return IdmtErrors.Tenant.AccessError;
            }
        }
    }

    public static RouteHandlerBuilder MapRevokeTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<NoContent, BadRequest, NotFound, ForbidHttpResult, UnauthorizedHttpResult, InternalServerError>> (
            Guid userId,
            string tenantIdentifier,
            IRevokeTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(userId, tenantIdentifier, cancellationToken);
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.Validation => TypedResults.BadRequest(),
                    ErrorType.NotFound => TypedResults.NotFound(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.Unauthorized => TypedResults.Unauthorized(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
        .WithSummary("Revoke user access from a tenant");
    }
}
