using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Idmt.Core.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// The application and identity context. Derives from <see cref="IdentityDbContext{TUser, TRole, TKey}"/>
/// and implements <see cref="IMultiTenantDbContext"/> so it keeps the IDMT identity model global while
/// still giving consumers Finbuckle stamping and filtering for their own <c>[MultiTenant]</c> entities.
/// </summary>
/// <remarks>
/// The IDMT identity model is global by construction: the base is the plain Identity context, so no
/// Identity table is Finbuckle-stamped and there is nothing to undo. <see cref="IdmtUser"/> is the
/// global canonical identity. <see cref="IdmtRole"/> is per-tenant via an explicit, declared
/// <c>TenantId</c> column scoped by explicit query, NOT by a Finbuckle filter: issuance projects a
/// user's role assignments into the token at the OpenIddict token endpoint, which runs with no ambient
/// tenant (see 06-tenant-access-gate.md). A Finbuckle filter there would compare against a null tenant
/// and return no rows. Consumers extend this context and mark their own tenant-scoped tables
/// <c>[MultiTenant]</c> / <c>IsMultiTenant()</c>; those are stamped on save by the
/// <see cref="MultiTenantDbContextExtensions.EnforceMultiTenant"/> call below and filtered on read by
/// their own marking. Not sealed.
/// </remarks>
public class IdmtDbContext : IdentityDbContext<IdmtUser, IdmtRole, Guid>, IMultiTenantDbContext
{
    /// <summary>Used by <c>AddDbContext&lt;IdmtDbContext&gt;</c>.</summary>
    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions<IdmtDbContext> options)
        : this(multiTenantContextAccessor, (DbContextOptions)options)
    {
    }

    /// <summary>
    /// Used by derived consumer contexts: <c>AddDbContext&lt;TConsumer&gt;</c> yields
    /// <c>DbContextOptions&lt;TConsumer&gt;</c>, which only a non-generic base constructor accepts.
    /// </summary>
    protected IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions options)
        : base(options)
    {
        TenantInfo = multiTenantContextAccessor.MultiTenantContext.TenantInfo;
    }

    /// <inheritdoc />
    public ITenantInfo? TenantInfo { get; }

    /// <inheritdoc />
    public TenantMismatchMode TenantMismatchMode => TenantMismatchMode.Throw;

    /// <inheritdoc />
    public TenantNotSetMode TenantNotSetMode => TenantNotSetMode.Throw;

    /// <summary>The user-to-tenant edge the issuance gate queries by (UserId, TenantId).</summary>
    public DbSet<TenantAccess> TenantAccess => Set<TenantAccess>();

    /// <summary>The machine-client-to-tenant edge the client-credentials gate queries.</summary>
    public DbSet<ClientTenantAccess> ClientTenantAccess => Set<ClientTenantAccess>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder); // Identity schema. No Identity table is stamped multi-tenant.

        builder.Entity<IdmtUser>(entity =>
        {
            entity.HasIndex(u => u.IsActive);
            entity.HasIndex(u => u.NormalizedEmail).IsUnique(); // globally unique, no TenantId
        });

        builder.Entity<IdmtRole>(entity =>
        {
            // Per-tenant uniqueness on the explicit TenantId column. NOT Finbuckle-managed:
            // no IsMultiTenant(), so no query filter is applied (issuance reads roles with
            // no ambient tenant; callers scope by explicit .Where(r => r.TenantId == tenant)).
            entity.HasIndex(r => new { r.TenantId, r.Name }).IsUnique();
        });

        builder.Entity<TenantAccess>(entity =>
        {
            entity.HasKey(ta => ta.Id);
            entity.HasIndex(ta => new { ta.UserId, ta.TenantId }).IsUnique();
            entity.HasIndex(ta => ta.TenantId);
            entity.HasIndex(ta => ta.IsActive);
            // ExpiresAt stays DateTimeOffset?; the gate evaluates expiry in memory (SQLite).
        });

        builder.Entity<ClientTenantAccess>(entity =>
        {
            entity.HasKey(ca => ca.Id);
            entity.HasIndex(ca => new { ca.ClientId, ca.TenantId }).IsUnique();
            entity.HasIndex(ca => ca.TenantId);
            entity.HasIndex(ca => ca.IsActive);
        });

        // Configure any [MultiTenant]-attributed entities a consumer adds. Consumers that mark
        // entities with IsMultiTenant() directly in their own configuration do not depend on this;
        // it covers the attribute-based path and matches Finbuckle's own base-context behavior.
        builder.ConfigureMultiTenant();
    }

    // Finbuckle write-side enforcement for consumer [MultiTenant] entities. EF calls the bool
    // overloads internally, so the enforcement belongs there. IDMT marks none of its own entities
    // multi-tenant, so EnforceMultiTenant is a no-op for IDMT's tables and never throws at the
    // no-ambient-tenant token endpoint.
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        this.EnforceMultiTenant();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override async Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        this.EnforceMultiTenant();
        return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken)
            .ConfigureAwait(false);
    }
}
