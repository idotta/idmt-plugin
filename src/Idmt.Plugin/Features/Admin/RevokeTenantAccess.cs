using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
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

    internal sealed class RevokeTenantAccessHandler(
        IServiceProvider serviceProvider,
        ITenantOperationService tenantOps,
        ILogger<RevokeTenantAccessHandler> logger) : IRevokeTenantAccessHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            IdmtUser? user;
            using (var scope = serviceProvider.CreateScope())
            {
                var sp = scope.ServiceProvider;

                try
                {
                    var dbContext = sp.GetRequiredService<IdmtDbContext>();
                    var userManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                    var tenantStore = sp.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();

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
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error revoking tenant access for user {UserId} and tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return IdmtErrors.Tenant.AccessError;
                }
            }

            return await tenantOps.ExecuteInTenantScopeAsync(tenantIdentifier, async sp =>
            {
                var userManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var targetUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);
                    if (targetUser is not null)
                    {
                        targetUser.IsActive = false;
                        await userManager.UpdateAsync(targetUser);
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
        return endpoints.MapDelete("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<NoContent, NotFound, InternalServerError>> (
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
                    ErrorType.NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.NoContent();
        })
        .WithSummary("Revoke user access from a tenant");
    }
}
