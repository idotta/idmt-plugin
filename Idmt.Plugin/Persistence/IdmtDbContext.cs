using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Finbuckle.MultiTenant.Identity.EntityFrameworkCore;
using Idmt.Plugin.Constants;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Persistence;

/// <summary>
/// Multi-tenant Identity DbContext that integrates with Finbuckle.MultiTenant
/// </summary>
public class IdmtDbContext
    : MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>
{
    private readonly ICurrentUserService _currentUserService;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<IdmtDbContext> _logger;

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor, ICurrentUserService currentUserService, TimeProvider timeProvider, ILogger<IdmtDbContext> logger)
        : base(multiTenantContextAccessor)
    {
        _currentUserService = currentUserService;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions<IdmtDbContext> options,
        ICurrentUserService currentUserService,
        TimeProvider timeProvider,
        ILogger<IdmtDbContext> logger)
        : base(multiTenantContextAccessor, options)
    {
        _currentUserService = currentUserService;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    protected IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions options,
        ICurrentUserService currentUserService,
        TimeProvider timeProvider,
        ILogger<IdmtDbContext> logger)
        : base(multiTenantContextAccessor, options)
    {
        _currentUserService = currentUserService;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Audit logs for tracking user actions.
    /// </summary>
    public DbSet<IdmtAuditLog> AuditLogs { get; set; } = null!;

    /// <summary>
    /// Tenant access for tracking which system users can access which tenants.
    /// </summary>
    public DbSet<TenantAccess> TenantAccess { get; set; } = null!;

    /// <summary>
    /// Revoked refresh token records for token revocation tracking.
    /// </summary>
    public DbSet<RevokedToken> RevokedTokens { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Store DateTimeOffset as UTC ticks (long) so that range comparisons are
        // translatable by all supported providers, including the SQLite provider
        // used in unit tests (which cannot translate DateTimeOffset text comparisons
        // in ExecuteDelete / ExecuteDeleteAsync).
        var dateTimeOffsetConverter = new ValueConverter<DateTimeOffset, long>(
            dto => dto.UtcTicks,
            ticks => new DateTimeOffset(ticks, TimeSpan.Zero));

        var nullableDateTimeOffsetConverter = new ValueConverter<DateTimeOffset?, long?>(
            dto => dto == null ? null : dto.Value.UtcTicks,
            ticks => ticks == null ? null : new DateTimeOffset(ticks.Value, TimeSpan.Zero));

        // Phase 1: IdmtUser is a global entity (no per-tenant filter). Email is globally unique.
        // The Finbuckle MultiTenantIdentityDbContext base implementation stamps every Identity
        // entity (including IdmtUser) as multi-tenant during base.OnModelCreating. We undo that
        // here on IdmtUser only so that:
        //   1. There is no shadow TenantId column,
        //   2. The legacy (NormalizedUserName, TenantId) unique index is dropped,
        //   3. Finbuckle's tenant query filter is not applied to IdmtUser.
        builder.Entity<IdmtUser>(entity =>
        {
            // Drop Finbuckle's auto-stamped multi-tenant annotation on IdmtUser.
            entity.Metadata.RemoveAnnotation("Finbuckle:MultiTenant");

            // Drop any indexes that referenced the shadow TenantId property — must be done
            // before the property itself is removed, otherwise EF Core throws.
            var legacyIndexes = entity.Metadata.GetIndexes()
                .Where(ix => ix.Properties.Any(p => string.Equals(p.Name, "TenantId", StringComparison.Ordinal)))
                .ToList();
            foreach (var ix in legacyIndexes)
            {
                entity.Metadata.RemoveIndex(ix);
            }

            // Drop the shadow TenantId property added by Finbuckle.
            var tenantIdProperty = entity.Metadata.FindProperty("TenantId");
            if (tenantIdProperty is not null)
            {
                entity.Metadata.RemoveProperty(tenantIdProperty);
            }

            // Clear any tenant-scoped query filter(s) that Finbuckle injected for IdmtUser.
            // EF Core 10 supports multiple named query filters; clear them all by name plus
            // the legacy unnamed filter.
            foreach (var filter in entity.Metadata.GetDeclaredQueryFilters().ToList())
            {
                if (filter.Key is { } key)
                {
                    entity.Metadata.SetQueryFilter(key, null);
                }
            }
            entity.Metadata.SetQueryFilter(null);

            entity.HasIndex(u => u.IsActive);
            entity.HasIndex(u => u.NormalizedEmail).IsUnique();
            entity.Property(u => u.LastLoginAt).HasConversion(nullableDateTimeOffsetConverter);
        });

        // Configure role entity with proper multi-tenant support
        builder.Entity<IdmtRole>(entity =>
        {
            entity.HasIndex(r => new { r.TenantId, r.Name }).IsUnique();
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
            entity.Property(a => a.Timestamp).HasConversion(dateTimeOffsetConverter);
        });

        // Configure tenant access
        builder.Entity<TenantAccess>(entity =>
        {
            entity.HasKey(ta => ta.Id);
            entity.HasIndex(ta => new { ta.UserId, ta.TenantId }).IsUnique();
            entity.HasIndex(ta => ta.TenantId);
            entity.HasIndex(ta => ta.IsActive);
            entity.Property(ta => ta.ExpiresAt).HasConversion(nullableDateTimeOffsetConverter);
        });

        // Configure revoked tokens
        builder.Entity<RevokedToken>(entity =>
        {
            entity.HasKey(rt => rt.TokenId);
            entity.Property(rt => rt.TokenId).HasMaxLength(128);
            entity.Property(rt => rt.RevokedAt).HasConversion(dateTimeOffsetConverter);
            entity.Property(rt => rt.ExpiresAt).HasConversion(dateTimeOffsetConverter);
            entity.HasIndex(rt => rt.ExpiresAt);
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
        try
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
                        Action = AuditAction.Created.ToString(),
                        Resource = entry.Entity.GetName(),
                        ResourceId = entry.Entity.GetId(),
                        Success = true,
                        Timestamp = _timeProvider.GetUtcNow(),
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
                        Action = AuditAction.Deleted.ToString(),
                        Resource = entry.Entity.GetName(),
                        ResourceId = entry.Entity.GetId(),
                        Success = true,
                        Timestamp = _timeProvider.GetUtcNow(),
                        IpAddress = _currentUserService.IpAddress,
                        UserAgent = _currentUserService.UserAgent,
                    });
                }
                else if (entry.State == EntityState.Modified)
                {
                    string details = string.Join("\n", entry.Properties
                        .Where(prop => prop.IsModified)
                        .Select(prop => prop.Metadata.Name));
                    AuditLogs.Add(new IdmtAuditLog
                    {
                        UserId = _currentUserService.UserId,
                        TenantId = entry.Entity.GetTenantId(),
                        Action = AuditAction.Modified.ToString(),
                        Resource = entry.Entity.GetName(),
                        ResourceId = entry.Entity.GetId(),
                        Details = details,
                        Success = true,
                        Timestamp = _timeProvider.GetUtcNow(),
                        IpAddress = _currentUserService.IpAddress,
                        UserAgent = _currentUserService.UserAgent,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Audit logging failed during SaveChangesAsync");
            foreach (var entry in ChangeTracker.Entries<IdmtAuditLog>()
                .Where(e => e.State == EntityState.Added).ToList())
            {
                entry.State = EntityState.Detached;
            }
        }

        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges() =>
        throw new NotSupportedException("Use SaveChangesAsync. Sync SaveChanges is not supported in IdmtDbContext.");
}