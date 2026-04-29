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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class RevokeTenantAccess
{
    public interface IRevokeTenantAccessHandler
    {
        Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    // Fix: inject IdmtDbContext, UserManager<IdmtUser>, and IMultiTenantStore<IdmtTenantInfo>
    // as constructor parameters rather than resolving them from a manually-created IServiceProvider
    // scope. The manual scope bypassed the request lifetime, causing audit-log fields that depend on
    // ICurrentUserService (resolved through the request scope) to be null.
    internal sealed class RevokeTenantAccessHandler(
        IdmtDbContext dbContext,
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ITenantOperationService tenantOps,
        ITokenRevocationService tokenRevocationService,
        ICurrentUserService currentUserService,
        ILogger<RevokeTenantAccessHandler> logger) : IRevokeTenantAccessHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            if (currentUserService.UserId is null)
            {
                return IdmtErrors.General.Unexpected;
            }

            if (userId == currentUserService.UserId.Value)
            {
                return IdmtErrors.General.SelfTarget;
            }

            IdmtUser? user;

            try
            {
                user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
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
                    .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == targetTenant.Id, cancellationToken);
                if (tenantAccess is null)
                {
                    return IdmtErrors.Tenant.AccessNotFound;
                }

                tenantAccess.IsActive = false;
                dbContext.TenantAccess.Update(tenantAccess);
                await dbContext.SaveChangesAsync(cancellationToken);

                // Revoke any active bearer tokens so the user cannot refresh after access is removed
                await tokenRevocationService.RevokeUserTokensAsync(userId, targetTenant.Id!, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error revoking tenant access for user {UserId} and tenant {TenantIdentifier}", userId, tenantIdentifier);
                return IdmtErrors.Tenant.AccessError;
            }

            return await tenantOps.ExecuteInTenantScopeAsync(tenantIdentifier, async sp =>
            {
                var tenantUserManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var targetUser = await tenantUserManager.Users.FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);
                    if (targetUser is not null)
                    {
                        targetUser.IsActive = false;
                        await tenantUserManager.UpdateAsync(targetUser);
                    }
                    return Result.Success;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error deactivating user {UserId} in tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return IdmtErrors.Tenant.AccessError;
                }
            }, requireActive: false);
        }
    }

    public static RouteHandlerBuilder MapRevokeTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<NoContent, BadRequest, NotFound, InternalServerError>> (
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
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
        .WithSummary("Revoke user access from a tenant");
    }
}
