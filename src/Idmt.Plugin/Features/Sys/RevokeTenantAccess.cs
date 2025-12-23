using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Sys;

public static class RevokeTenantAccess
{
    public interface IRevokeTenantAccessHandler
    {
        Task<bool> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    internal sealed class RevokeTenantAccessHandler(
        IServiceProvider serviceProvider,
        ILogger<RevokeTenantAccessHandler> logger) : IRevokeTenantAccessHandler
    {
        public async Task<bool> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default)
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
                        return false;
                    }

                    var targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                    if (targetTenant is null)
                    {
                        return false;
                    }

                    var tenantAccess = await dbContext.TenantAccess
                        .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == targetTenant.Id, cancellationToken);
                    if (tenantAccess is not null)
                    {
                        tenantAccess.IsActive = false;
                        dbContext.TenantAccess.Update(tenantAccess);
                    }
                    await dbContext.SaveChangesAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error granting tenant access to user {UserId} for tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return false;
                }
            }

            using (var scope = serviceProvider.CreateScope())
            {
                var sp = scope.ServiceProvider;

                var provider = scope.ServiceProvider;

                var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
                var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenantInfo is null || !tenantInfo.IsActive)
                {
                    return false;
                }
                // Set Tenant Context BEFORE resolving DbContext/Managers
                var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
                var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
                tenantContextSetter.MultiTenantContext = tenantContext;

                var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var targetUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);
                    if (targetUser is null)
                    {
                        return true;
                    }
                    else
                    {
                        targetUser.IsActive = false;
                        await userManager.UpdateAsync(targetUser);
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error deactivating user {UserId} in tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return false;
                }
            }
        }
    }

    public static RouteHandlerBuilder MapRevokeTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}/tenants/{tenantId}", async Task<Results<Ok, NotFound<string>>> (
            Guid userId,
            string tenantId,
            IRevokeTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
        {
            var success = await handler.HandleAsync(userId, tenantId, cancellationToken);
            return success
                ? TypedResults.Ok()
                : TypedResults.NotFound("User or Tenant not found, or operation failed.");
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Revoke user access from a tenant");
    }
}
