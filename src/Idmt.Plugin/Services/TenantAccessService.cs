using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Services;

internal sealed class TenantAccessService(
    IdmtDbContext dbContext,
    IMultiTenantContextAccessor tenantAccessor,
    ITenantResolver<IdmtTenantInfo> tenantResolver,
    IMultiTenantContextSetter tenantContextSetter,
    IMultiTenantStore<IdmtTenantInfo> tenantStore,
    ICurrentUserService currentUserService) : ITenantAccessService
{
    public async Task<IdmtTenantInfo[]> GetUserAccessibleTenantsAsync(Guid userId)
    {
        var tenantIds = await dbContext.TenantAccess
            .Where(ta => ta.UserId == userId && ta.IsActive)
            .Select(ta => ta.TenantId)
            .ToArrayAsync();

        var tenantTasks = tenantIds.Select(tenantStore.GetAsync);
        var tenants = await Task.WhenAll(tenantTasks);

        return tenants.Where(t => t != null).ToArray()!;
    }

    public async Task<bool> CanAccessTenantAsync(Guid userId, string tenantId)
    {
        return await dbContext.TenantAccess
            .AnyAsync(ta =>
                ta.UserId == userId &&
                ta.TenantId == tenantId &&
                ta.IsActive &&
                (ta.ExpiresAt == null || ta.ExpiresAt > DT.UtcNow));
    }

    public async Task<bool> GrantTenantAccessAsync(Guid userId, string tenantId, DateTime? expiresAt = null)
    {
        var previousMode = dbContext.TenantMismatchMode;
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;

        try
        {
            var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null)
            {
                return false;
            }

            var targetTenant = await tenantResolver.ResolveAsync(tenantId);
            if (targetTenant is null)
            {
                return false;
            }

            var userRoleIds = await dbContext.UserRoles
                .Where(ur => ur.UserId == userId)
                .Select(ur => ur.RoleId)
                .ToListAsync();

            var tenantAccess = await dbContext.TenantAccess
                .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);

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
                    TenantId = tenantId,
                    IsActive = true,
                    ExpiresAt = expiresAt
                };
                dbContext.TenantAccess.Add(tenantAccess);
            }

            var currentTenant = tenantAccessor.MultiTenantContext;

            try
            {
                // Temporary set the tenant context to the target tenant
                tenantContextSetter.MultiTenantContext = targetTenant;

                var targetUser = await dbContext.Users
                    .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName && u.TenantId == tenantId);

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
                        IsActive = true,
                        TenantId = tenantId
                    };

                    dbContext.Users.Add(targetUser);

                    // Copy roles from system user to target tenant user
                    foreach (var roleId in userRoleIds)
                    {
                        var userRole = new IdentityUserRole<Guid>
                        {
                            UserId = targetUser.Id,
                            RoleId = roleId
                        };
                        dbContext.UserRoles.Add(userRole);
                    }
                }
                else
                {
                    targetUser.IsActive = true;
                    dbContext.Users.Update(targetUser);
                }

                await dbContext.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                tenantContextSetter.MultiTenantContext = currentTenant;
            }

            return true;
        }
        finally
        {
            dbContext.TenantMismatchMode = previousMode;
        }
    }

    public async Task<bool> RevokeTenantAccessAsync(Guid userId, string tenantId)
    {
        var previousMode = dbContext.TenantMismatchMode;
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;

        try
        {
            var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null)
            {
                return false;
            }

            var targetTenant = await tenantResolver.ResolveAsync(tenantId);
            if (targetTenant is null)
            {
                return false;
            }

            var tenantAccess = await dbContext.TenantAccess
                .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);

            if (tenantAccess is null)
            {
                return true;
            }

            tenantAccess.IsActive = false;
            dbContext.TenantAccess.Update(tenantAccess);

            var currentTenant = tenantAccessor.MultiTenantContext;

            try
            {
                tenantContextSetter.MultiTenantContext = targetTenant;

                var targetUser = await dbContext.Users
                    .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName && u.TenantId == tenantId);

                if (targetUser is not null)
                {
                    targetUser.IsActive = false;
                    dbContext.Users.Update(targetUser);
                }

                await dbContext.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                tenantContextSetter.MultiTenantContext = currentTenant;
            }

            return true;
        }
        finally
        {
            dbContext.TenantMismatchMode = previousMode;
        }
    }

    public bool CanAssignRole(string role)
    {
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.SysAdmin))
        {
            return true;
        }
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.SysSupport) && role != IdmtDefaultRoleTypes.SysAdmin)
        {
            return true;
        }
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.TenantAdmin) &&
            role != IdmtDefaultRoleTypes.SysAdmin &&
            role != IdmtDefaultRoleTypes.SysSupport)
        {
            return true;
        }
        return false;
    }

    public bool CanManageUser(IEnumerable<string> targetUserRoles)
    {
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.SysAdmin))
        {
            return true;
        }
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.SysSupport) &&
            !targetUserRoles.Contains(IdmtDefaultRoleTypes.SysAdmin))
        {
            return true;
        }
        if (currentUserService.IsInRole(IdmtDefaultRoleTypes.TenantAdmin) &&
            !targetUserRoles.Contains(IdmtDefaultRoleTypes.SysAdmin) &&
            !targetUserRoles.Contains(IdmtDefaultRoleTypes.SysSupport))
        {
            return true;
        }
        return false;
    }
}
