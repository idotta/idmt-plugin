using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idotta.Idmt.Plugin.Models;

namespace Idotta.Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant Identity DbContext that integrates with Finbuckle.MultiTenant
/// </summary>
public class IdmtDbContext : IdentityDbContext<IdmtUser, IdmtRole, string>, IMultiTenantDbContext
{
    public ITenantInfo TenantInfo { get; set; } = null!;
    public TenantMismatchMode TenantMismatchMode { get; set; } = TenantMismatchMode.Throw;
    public TenantNotSetMode TenantNotSetMode { get; set; } = TenantNotSetMode.Throw;

    public IdmtDbContext(DbContextOptions<IdmtDbContext> options)
        : base(options)
    {
    }

    public IdmtDbContext(DbContextOptions<IdmtDbContext> options, ITenantInfo tenantInfo)
        : base(options)
    {
        TenantInfo = tenantInfo;
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure multi-tenancy for Identity entities
        builder.Entity<IdmtUser>().IsMultiTenant();
        builder.Entity<IdmtRole>().IsMultiTenant();
        builder.Entity<Microsoft.AspNetCore.Identity.IdentityUserRole<string>>().IsMultiTenant();
        builder.Entity<Microsoft.AspNetCore.Identity.IdentityUserClaim<string>>().IsMultiTenant();
        builder.Entity<Microsoft.AspNetCore.Identity.IdentityUserLogin<string>>().IsMultiTenant();
        builder.Entity<Microsoft.AspNetCore.Identity.IdentityUserToken<string>>().IsMultiTenant();
        builder.Entity<Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>>().IsMultiTenant();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (TenantInfo != null)
        {
            // Configure tenant-specific options if needed
        }

        base.OnConfiguring(optionsBuilder);
    }
}