using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Services;

internal sealed class TenantAccessService(
    IdmtDbContext dbContext,
    ICurrentUserService currentUserService) : ITenantAccessService
{
    public async Task<bool> CanAccessTenantAsync(Guid userId, string tenantId)
    {
        return await dbContext.TenantAccess
            .AnyAsync(ta =>
                ta.UserId == userId &&
                ta.TenantId == tenantId &&
                ta.IsActive &&
                (ta.ExpiresAt == null || ta.ExpiresAt > DT.UtcNow));
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
