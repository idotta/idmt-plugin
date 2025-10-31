using Microsoft.EntityFrameworkCore;
using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Finbuckle.MultiTenant.Abstractions;

namespace Idmt.Plugin.Persistence;

/// <summary>
/// Multi-tenant Identity DbContext that integrates with Finbuckle.MultiTenant
/// </summary>
public class IdmtDbContext
    : MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>
{
    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor)
        : base(multiTenantContextAccessor)
    {
    }

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions options)
        : base(multiTenantContextAccessor, options)
    {
    }

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions<IdmtDbContext> options)
        : base(multiTenantContextAccessor, options)
    {
    }

    /// <summary>
    /// User permissions for fine-grained access control.
    /// </summary>
    public DbSet<UserPermission> UserPermissions { get; set; } = null!;

    /// <summary>
    /// Audit logs for tracking user actions.
    /// </summary>
    public DbSet<IdmtAuditLog> IdentityAuditLogs { get; set; } = null!;

    /// <summary>
    /// Tenant access for tracking which system users can access which tenants.
    /// </summary>
    public DbSet<TenantAccess> TenantAccess { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure user entity with proper multi-tenant support
        builder.Entity<IdmtUser>(entity =>
        {
            entity.HasIndex(u => u.IsActive);
            entity.HasIndex(u => new { u.Email, u.UserName, u.TenantId }).IsUnique();
            entity.IsMultiTenant();
        });

        // Configure user permissions
        builder.Entity<UserPermission>(entity =>
        {
            entity.HasKey(p => p.Id);

            entity.HasOne<IdmtUser>()
                .WithMany()
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(p => new { p.UserId, p.Permission });
            entity.HasIndex(p => new { p.TenantId, p.Permission });
            entity.HasIndex(p => p.IsActive);

            entity.IsMultiTenant();
        });

        // Configure audit logs
        builder.Entity<IdmtAuditLog>(entity =>
        {
            entity.HasKey(a => a.Id);
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => new { a.UserId, a.Timestamp });
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => a.Action);
        });

        // Configure tenant access
        builder.Entity<TenantAccess>(entity =>
        {
            entity.HasKey(ta => ta.Id);
            entity.HasIndex(ta => new { ta.UserId, ta.TenantId });
            entity.HasIndex(ta => ta.TenantId);
            entity.HasIndex(ta => ta.IsActive);
        });
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