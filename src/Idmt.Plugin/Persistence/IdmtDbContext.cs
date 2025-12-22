using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Finbuckle.MultiTenant.Identity.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Persistence;

/// <summary>
/// Multi-tenant Identity DbContext that integrates with Finbuckle.MultiTenant
/// </summary>
public class IdmtDbContext
    : MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>
{
    private readonly ICurrentUserService _currentUserService;

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor, ICurrentUserService currentUserService)
        : base(multiTenantContextAccessor)
    {
        _currentUserService = currentUserService;
    }

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions<IdmtDbContext> options,
        ICurrentUserService currentUserService)
        : base(multiTenantContextAccessor, options)
    {
        _currentUserService = currentUserService;
    }

    protected IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions options,
        ICurrentUserService currentUserService)
        : base(multiTenantContextAccessor, options)
    {
        _currentUserService = currentUserService;
    }

    /// <summary>
    /// Audit logs for tracking user actions.
    /// </summary>
    public DbSet<IdmtAuditLog> AuditLogs { get; set; } = null!;

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

        // Configure TenantInfo - IdmtTenantStoreDbContext accesses this table but doesn't configure it
        builder.Entity<IdmtTenantInfo>(entity =>
        {
            entity.ToTable("TenantInfo");
            entity.HasKey(ti => ti.Id);
            entity.Property(ti => ti.Id).HasMaxLength(64);
            entity.HasIndex(ti => ti.Identifier).IsUnique();

            // Indexes for common queries on custom properties
            entity.HasIndex(ti => ti.IsActive);

            // Property configurations for custom properties
            entity.Property(ti => ti.Name).HasMaxLength(200);
            entity.Property(ti => ti.DisplayName).HasMaxLength(200);
            entity.Property(ti => ti.Plan).HasMaxLength(100);
            entity.Property(ti => ti.IsActive).IsRequired().HasDefaultValue(true);

            // Authentication paths with defaults
            entity.Property(ti => ti.LoginPath).HasMaxLength(256).HasDefaultValue("/login");
            entity.Property(ti => ti.LogoutPath).HasMaxLength(256).HasDefaultValue("/logout");
            entity.Property(ti => ti.AccessDeniedPath).HasMaxLength(256).HasDefaultValue("/access-denied");
        });
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        var entries = ChangeTracker.Entries<IAuditable>().ToArray();

        foreach (var entry in entries)
        {
            if (entry.State == EntityState.Added)
            {
                AuditLogs.Add(new IdmtAuditLog
                {
                    UserId = _currentUserService.UserId,
                    TenantId = entry.Entity.GetTenantId(),
                    Action = "Created",
                    Resource = entry.Entity.GetName(),
                    ResourceId = entry.Entity.GetId(),
                    Success = true,
                    Timestamp = DT.UtcNow,
                    IpAddress = _currentUserService.IpAddress,
                    UserAgent = _currentUserService.UserAgent,
                });
            }
            else if (entry.State == EntityState.Deleted)
            {
                AuditLogs.Add(new IdmtAuditLog
                {
                    UserId = _currentUserService.UserId,
                    TenantId = entry.Entity.GetTenantId(),
                    Action = "Deleted",
                    Resource = entry.Entity.GetName(),
                    ResourceId = entry.Entity.GetId(),
                    Success = true,
                    Timestamp = DT.UtcNow,
                    IpAddress = _currentUserService.IpAddress,
                    UserAgent = _currentUserService.UserAgent,
                });
            }
            else if (entry.State == EntityState.Modified)
            {
                string details = string.Join(", ", entry.Properties
                    .Where(prop => prop.IsModified)
                    .Select(prop => prop.Metadata.Name));
                AuditLogs.Add(new IdmtAuditLog
                {
                    UserId = _currentUserService.UserId,
                    TenantId = entry.Entity.GetTenantId(),
                    Action = "Modified",
                    Resource = entry.Entity.GetName(),
                    ResourceId = entry.Entity.GetId(),
                    Details = details,
                    Success = true,
                    Timestamp = DT.UtcNow,
                    IpAddress = _currentUserService.IpAddress,
                    UserAgent = _currentUserService.UserAgent,
                });
            }
        }

        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges() =>
        SaveChangesAsync(CancellationToken.None).GetAwaiter().GetResult();
}