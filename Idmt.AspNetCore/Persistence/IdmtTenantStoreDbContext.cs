using Finbuckle.MultiTenant.EntityFrameworkCore.Stores;
using Idmt.AspNetCore.MultiTenancy;
using Microsoft.EntityFrameworkCore;

namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// The dedicated tenant-store context that persists the <see cref="IdmtTenantInfo"/>
/// metadata Finbuckle resolves against. Owns the tenant-info table in its own
/// migration history, separate from the application context.
/// </summary>
public sealed class IdmtTenantStoreDbContext : EFCoreStoreDbContext<IdmtTenantInfo>
{
    public IdmtTenantStoreDbContext(DbContextOptions<IdmtTenantStoreDbContext> options)
        : base(options)
    {
    }
}
