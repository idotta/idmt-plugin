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

namespace Idmt.Plugin.Features.Admin;

public static class RevokeTenantAccess
{
    public interface IRevokeTenantAccessHandler
    {
        Task<Result> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    internal sealed class RevokeTenantAccessHandler(
        IServiceProvider serviceProvider,
        ILogger<RevokeTenantAccessHandler> logger) : IRevokeTenantAccessHandler
    {
        public async Task<Result> HandleAsync(Guid userId, string tenantIdentifier, CancellationToken cancellationToken = default)
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
                        return Result.Failure("User not found", StatusCodes.Status404NotFound);
                    }

                    var targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                    if (targetTenant is null)
                    {
                        return Result.Failure("Tenant not found", StatusCodes.Status404NotFound);
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
                    logger.LogError(ex, "Error revoking tenant access for user {UserId} and tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return Result.Failure("An error occurred while revoking tenant access", StatusCodes.Status500InternalServerError);
                }
            }

            using (var scope = serviceProvider.CreateScope())
            {
                var sp = scope.ServiceProvider;

                var tenantStore = sp.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
                var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenantInfo is null)
                {
                    return Result.Failure("Tenant not found", StatusCodes.Status404NotFound);
                }
                // Set Tenant Context BEFORE resolving DbContext/Managers
                var tenantContextSetter = sp.GetRequiredService<IMultiTenantContextSetter>();
                var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
                tenantContextSetter.MultiTenantContext = tenantContext;

                var userManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var targetUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);
                    if (targetUser is null)
                    {
                        return Result.Success();
                    }
                    else
                    {
                        targetUser.IsActive = false;
                        await userManager.UpdateAsync(targetUser);
                    }
                    return Result.Success();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error deactivating user {UserId} in tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return Result.Failure("An error occurred while deactivating user", StatusCodes.Status500InternalServerError);
                }
            }
        }
    }

    public static RouteHandlerBuilder MapRevokeTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<Ok, NotFound, InternalServerError>> (
            Guid userId,
            string tenantId,
            IRevokeTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(userId, tenantId, cancellationToken);
            if (!result.IsSuccess)
            {
                return result.StatusCode switch
                {
                    StatusCodes.Status404NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Revoke user access from a tenant");
    }
}
