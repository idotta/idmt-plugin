using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Finbuckle.MultiTenant.EntityFrameworkCore.Stores;
using Idmt.Spike.Host.Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Spike.Host.Persistence;

/// <summary>
/// Global identity + the TenantAccess gate edge. Plain (non-multi-tenant):
/// users are global canonical rows, and the issuance gate must query
/// TenantAccess by (userId, tenantId) at the token endpoint where there is no
/// ambient tenant. Mirrors v1's de-tenanted IdmtUser reality.
/// </summary>
public sealed class IdmtIdentityDbContext(DbContextOptions<IdmtIdentityDbContext> options)
    : IdentityDbContext<IdmtUser, IdmtRole, Guid>(options)
{
    public DbSet<TenantAccess> TenantAccess => Set<TenantAccess>();
}

/// <summary>
/// Finbuckle multi-tenant app data. Holds only TenantWidget, whose TenantId is
/// stamped on save under the ambient tenant — the "Finbuckle stamps" half of
/// gate 4, proven to coexist with the tenant-agnostic OpenIddict stores.
/// </summary>
public sealed class IdmtTenantDbContext(
    IMultiTenantContextAccessor accessor,
    DbContextOptions<IdmtTenantDbContext> options)
    : MultiTenantDbContext(accessor, options)
{
    public DbSet<TenantWidget> Widgets => Set<TenantWidget>();
}

/// <summary>
/// Tenant-agnostic OpenIddict store. A PLAIN DbContext (never
/// MultiTenantDbContext), so Finbuckle never stamps or filters the OAuth tables.
/// Also hosts SupportAudit so a support-token insert and its audit row share one
/// context/transaction (gate 2). This is the heart of gate 4.
/// </summary>
public sealed class IdmtOpenIddictDbContext(DbContextOptions<IdmtOpenIddictDbContext> options)
    : DbContext(options)
{
    public DbSet<SupportAudit> SupportAudits => Set<SupportAudit>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();
    }
}

/// <summary>Finbuckle EFCore tenant-metadata store (the TenantInfo table).</summary>
public sealed class IdmtTenantStoreDbContext : EFCoreStoreDbContext<IdmtTenantInfo>
{
    public IdmtTenantStoreDbContext(DbContextOptions<IdmtTenantStoreDbContext> options) : base(options) { }
}
