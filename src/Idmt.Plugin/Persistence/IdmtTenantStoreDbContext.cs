using Microsoft.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Finbuckle.MultiTenant.EntityFrameworkCore.Stores;

namespace Idmt.Plugin.Persistence;

/// <summary>
/// Lightweight DbContext for Finbuckle.MultiTenant EFCore store.
/// This context accesses the TenantInfo table but does NOT configure it.
/// All table configuration is done in IdmtDbContext for simplified migrations.
/// Both contexts share the same database connection.
/// </summary>
public class IdmtTenantStoreDbContext : EFCoreStoreDbContext<IdmtTenantInfo>
{
    public IdmtTenantStoreDbContext(DbContextOptions<IdmtTenantStoreDbContext> options) : base(options)
    {
    }

    protected IdmtTenantStoreDbContext(DbContextOptions options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // IdmtDbContext owns all table configurations
        // This keeps migrations simple: only run dotnet ef migrations with IdmtDbContext
    }
}
