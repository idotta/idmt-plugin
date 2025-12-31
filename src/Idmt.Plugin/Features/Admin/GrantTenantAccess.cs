using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class GrantTenantAccess
{
    public sealed record GrantAccessRequest(DateTime? ExpiresAt);

    public interface IGrantTenantAccessHandler
    {
        Task<Result> HandleAsync(Guid userId, string tenantIdentifier, DateTime? expiresAt = null, CancellationToken cancellationToken = default);
    }

    internal sealed class GrantTenantAccessHandler(
        IServiceProvider serviceProvider,
        ILogger<GrantTenantAccessHandler> logger
        ) : IGrantTenantAccessHandler
    {
        public async Task<Result> HandleAsync(Guid userId, string tenantIdentifier, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
        {
            IdmtUser? user = null;
            IdmtTenantInfo? targetTenant = null;
            IList<string> userRoles = [];
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

                    targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                    if (targetTenant is null)
                    {
                        return Result.Failure("Tenant not found", StatusCodes.Status404NotFound);
                    }

                    userRoles = await userManager.GetRolesAsync(user);
                    if (userRoles.Count == 0)
                    {
                        logger.LogWarning("User {UserId} has no roles assigned; cannot grant tenant access.", userId);
                        return Result.Failure("User has no roles assigned", StatusCodes.Status400BadRequest);
                    }

                    var tenantAccess = await dbContext.TenantAccess
                        .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == targetTenant.Id, cancellationToken);
                    if (tenantAccess is not null)
                    {
                        tenantAccess.IsActive = true;
                        tenantAccess.ExpiresAt = expiresAt;
                        dbContext.TenantAccess.Update(tenantAccess);
                    }
                    else
                    {
                        tenantAccess = new TenantAccess
                        {
                            UserId = userId,
                            TenantId = targetTenant.Id,
                            IsActive = true,
                            ExpiresAt = expiresAt
                        };
                        dbContext.TenantAccess.Add(tenantAccess);
                    }
                    await dbContext.SaveChangesAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error granting tenant access to user {UserId} for tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return Result.Failure("An error occurred while granting tenant access", StatusCodes.Status500InternalServerError);
                }
            }

            using (var scope = serviceProvider.CreateScope())
            {
                var sp = scope.ServiceProvider;

                var tenantStore = sp.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
                var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenantInfo is null || !tenantInfo.IsActive)
                {
                    return Result.Failure("Tenant not found or inactive", StatusCodes.Status404NotFound);
                }
                // Set Tenant Context BEFORE resolving DbContext/Managers
                var tenantContextSetter = sp.GetRequiredService<IMultiTenantContextSetter>();
                var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
                tenantContextSetter.MultiTenantContext = tenantContext;

                try
                {
                    var targetUserManager = sp.GetRequiredService<UserManager<IdmtUser>>();

                    var targetUser = await targetUserManager.Users
                        .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);

                    if (targetUser is null)
                    {
                        // Create new user record for the target tenant
                        targetUser = new IdmtUser
                        {
                            UserName = user.UserName,
                            Email = user.Email,
                            EmailConfirmed = user.EmailConfirmed,
                            PasswordHash = user.PasswordHash,
                            SecurityStamp = user.SecurityStamp,
                            ConcurrencyStamp = user.ConcurrencyStamp,
                            PhoneNumber = user.PhoneNumber,
                            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                            TwoFactorEnabled = user.TwoFactorEnabled,
                            LockoutEnd = user.LockoutEnd,
                            LockoutEnabled = user.LockoutEnabled,
                            AccessFailedCount = user.AccessFailedCount,
                            IsActive = true
                        };

                        await targetUserManager.CreateAsync(targetUser);
                        await targetUserManager.AddToRolesAsync(targetUser, userRoles);
                    }
                    else
                    {
                        targetUser.IsActive = true;
                        await targetUserManager.UpdateAsync(targetUser);
                    }

                    return Result.Success();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error granting tenant access to user {UserId} in tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return Result.Failure("An error occurred while granting tenant access", StatusCodes.Status500InternalServerError);
                }
            }
        }
    }

    public static RouteHandlerBuilder MapGrantTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<Ok, BadRequest, NotFound, InternalServerError>> (
            Guid userId,
            string tenantIdentifier,
            [FromBody] GrantAccessRequest request,
            IGrantTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(userId, tenantIdentifier, request.ExpiresAt, cancellationToken);
            if (!result.IsSuccess)
            {
                return result.StatusCode switch
                {
                    StatusCodes.Status400BadRequest => TypedResults.BadRequest(),
                    StatusCodes.Status404NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError()
                };
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Grant user access to a tenant");
    }
}
