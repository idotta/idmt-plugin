using Microsoft.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Finbuckle.MultiTenant.EntityFrameworkCore.Stores.EFCoreStore;

namespace Idmt.Plugin.Persistence;

public class IdmtTenantStoreDbContext : EFCoreStoreDbContext<IdmtTenantInfo>
{
    public IdmtTenantStoreDbContext(DbContextOptions options) : base(options)
    {
    }

    public IdmtTenantStoreDbContext(DbContextOptions<IdmtTenantStoreDbContext> options) : base(options)
    {
    }
}
