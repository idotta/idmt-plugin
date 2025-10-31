using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Services;

internal sealed class TenantAccessService(
    IdmtDbContext dbContext,
    ICurrentUserService currentUserService,
    IMultiTenantContextAccessor tenantAccessor,
    ITenantResolver<IdmtTenantInfo> tenantResolver,
    IMultiTenantContextSetter tenantContextSetter) : ITenantAccessService
{
    public async Task<string[]> GetUserAccessibleTenantsAsync(Guid userId)
    {
        return await dbContext.TenantAccess
            .Where(ta => ta.UserId == userId && ta.IsActive)
            .Select(ta => ta.TenantId)
            .ToArrayAsync();
    }

    public async Task<bool> CanAccessTenantAsync(Guid userId, string tenantId)
    {
        return await dbContext.TenantAccess
            .AnyAsync(ta =>
                ta.UserId == userId &&
                ta.TenantId == tenantId &&
                ta.IsActive &&
                (ta.ExpiresAt == null || ta.ExpiresAt > DateTime.UtcNow));
    }

    public async Task<bool> GrantTenantAccessAsync(Guid userId, string tenantId, DateTime? expiresAt = null)
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
            tenantAccess.GrantedAt = DateTime.UtcNow;
            tenantAccess.GrantedBy = currentUserService.UserId;
            tenantAccess.ExpiresAt = expiresAt;
            dbContext.TenantAccess.Update(tenantAccess);
        }
        else
        {
            tenantAccess = new TenantAccess
            {
                UserId = userId,
                TenantId = tenantId,
                GrantedAt = DateTime.UtcNow,
                GrantedBy = currentUserService.UserId,
                IsActive = true,
                ExpiresAt = expiresAt
            };
            dbContext.TenantAccess.Add(tenantAccess);
        }

        var currentTenant = tenantAccessor.MultiTenantContext;
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;
        try
        {
            // Temporary set the tenant context to the target tenant
            tenantContextSetter.MultiTenantContext = targetTenant;

            var targetUser = await dbContext.Users
                .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName && u.TenantId == tenantId);

            bool userExists = targetUser is not null;
            targetUser ??= user;

            targetUser.TenantId = tenantId;
            targetUser.IsActive = true;
            targetUser.UpdatedAt = DateTime.UtcNow;
            targetUser.UpdatedBy = currentUserService.UserId ?? Guid.Empty;

            if (userExists)
            {
                dbContext.Users.Update(targetUser);
            }
            else
            {
                dbContext.Users.Add(targetUser);
            }

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
            await dbContext.SaveChangesAsync();
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            tenantContextSetter.MultiTenantContext = currentTenant;
            dbContext.TenantMismatchMode = TenantMismatchMode.Throw;
        }

        return true;
    }

    public async Task<bool> RevokeTenantAccessAsync(Guid userId, string tenantId)
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
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;
        try
        {
            tenantContextSetter.MultiTenantContext = targetTenant;

            var targetUser = await dbContext.Users
                .FirstOrDefaultAsync(u => u.Email == user.Email && u.UserName == user.UserName && u.TenantId == tenantId);

            if (targetUser is not null)
            {
                targetUser.IsActive = false;
                targetUser.UpdatedAt = DateTime.UtcNow;
                targetUser.UpdatedBy = currentUserService.UserId ?? Guid.Empty;
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
            dbContext.TenantMismatchMode = TenantMismatchMode.Throw;
        }

        return true;
    }
}