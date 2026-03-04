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
        Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTime? expiresAt = null, CancellationToken cancellationToken = default);
    }

    internal sealed class GrantTenantAccessHandler(
        IServiceProvider serviceProvider,
        ITenantOperationService tenantOps,
        TimeProvider timeProvider,
        ILogger<GrantTenantAccessHandler> logger
        ) : IGrantTenantAccessHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
        {
            if (expiresAt.HasValue && expiresAt.Value <= timeProvider.GetUtcNow().UtcDateTime)
            {
                return Error.Validation("ExpiresAt", "Expiration date must be in the future");
            }

            IdmtUser? user = null;
            IdmtTenantInfo? targetTenant = null;
            IList<string> userRoles = [];
            using (var scope = serviceProvider.CreateScope())
            {
                var sp = scope.ServiceProvider;

                var dbContext = sp.GetRequiredService<IdmtDbContext>();
                try
                {
                    var userManager = sp.GetRequiredService<UserManager<IdmtUser>>();
                    var tenantStore = sp.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();

                    user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
                    if (user is null)
                    {
                        return IdmtErrors.User.NotFound;
                    }

                    targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                    if (targetTenant is null)
                    {
                        return IdmtErrors.Tenant.NotFound;
                    }

                    if (!targetTenant.IsActive)
                    {
                        return IdmtErrors.Tenant.Inactive;
                    }

                    userRoles = await userManager.GetRolesAsync(user);
                    if (userRoles.Count == 0)
                    {
                        logger.LogWarning("User {UserId} has no roles assigned; cannot grant tenant access.", userId);
                        return IdmtErrors.User.NoRolesAssigned;
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
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error granting tenant access to user {UserId} for tenant {TenantIdentifier}", userId, tenantIdentifier);
                    return IdmtErrors.Tenant.AccessError;
                }

                // Execute tenant-scope operation BEFORE persisting TenantAccess to prevent orphaned records
                var tenantResult = await tenantOps.ExecuteInTenantScopeAsync(tenantIdentifier, async tsp =>
                {
                    try
                    {
                        var targetUserManager = tsp.GetRequiredService<UserManager<IdmtUser>>();

                        var targetUser = await targetUserManager.Users
                            .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName, cancellationToken);

                        if (targetUser is null)
                        {
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

                            var createResult = await targetUserManager.CreateAsync(targetUser);
                            if (!createResult.Succeeded)
                            {
                                logger.LogError("Failed to create user in target tenant: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                                return IdmtErrors.Tenant.AccessError;
                            }
                            var roleResult = await targetUserManager.AddToRolesAsync(targetUser, userRoles);
                            if (!roleResult.Succeeded)
                            {
                                logger.LogError("Failed to assign roles in target tenant: {Errors}", string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                                return IdmtErrors.Tenant.AccessError;
                            }
                        }
                        else
                        {
                            targetUser.IsActive = true;
                            await targetUserManager.UpdateAsync(targetUser);
                        }

                        return Result.Success;
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Error granting tenant access to user {UserId} in tenant {TenantIdentifier}", userId, tenantIdentifier);
                        return IdmtErrors.Tenant.AccessError;
                    }
                });

                if (tenantResult.IsError)
                {
                    return tenantResult;
                }

                // Tenant-scope operation succeeded — now persist the TenantAccess record
                await dbContext.SaveChangesAsync(cancellationToken);
                return Result.Success;
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
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.Validation => TypedResults.BadRequest(),
                    ErrorType.NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .WithSummary("Grant user access to a tenant");
    }
}
