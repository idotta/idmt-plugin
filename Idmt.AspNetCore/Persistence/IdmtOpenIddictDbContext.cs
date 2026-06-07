using Microsoft.EntityFrameworkCore;

namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// The tenant-agnostic OpenIddict store. A plain <see cref="DbContext"/> that
/// never derives from Finbuckle's <c>MultiTenantDbContext</c>, so Finbuckle never
/// stamps or filters its tables. The token endpoint runs with no ambient tenant;
/// tenant binding lives in the token's <c>aud</c> claim and the per-request
/// audience handler, never in a column on the token entry (gate 4, criterion 3).
/// </summary>
/// <remarks>
/// Also hosts <see cref="SupportAudit"/> so a support-token insert and its audit
/// row share one context and one transaction (gate 2; see 08-support-token-mint.md).
/// </remarks>
public sealed class IdmtOpenIddictDbContext : DbContext
{
    public IdmtOpenIddictDbContext(DbContextOptions<IdmtOpenIddictDbContext> options)
        : base(options)
    {
    }

    public DbSet<SupportAudit> SupportAudits => Set<SupportAudit>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();
    }
}
