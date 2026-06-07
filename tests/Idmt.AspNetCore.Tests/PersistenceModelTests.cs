using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions;
using Microsoft.Data.Sqlite;
using Idmt.AspNetCore.MultiTenancy;
using Idmt.AspNetCore.Persistence;
using Idmt.Core.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idmt.AspNetCore.Tests;

/// <summary>
/// Model-level gate-4 assertions, checkable without a running server. The
/// behavioral halves (token endpoint issues with no ambient tenant; Finbuckle
/// stamps an app entity) require the OpenIddict server (04) and Finbuckle
/// resolution (05) and are covered by the integration suite (14).
/// </summary>
public class PersistenceModelTests
{
    // Finbuckle's MultiTenantDbContext reads the accessor in its constructor; a
    // resolved-nothing context is enough to build the model.
    private sealed class NullMultiTenantContext : IMultiTenantContext
    {
        public ITenantInfo? TenantInfo { get; init; }
        public StrategyInfo? StrategyInfo { get; init; }
        public bool IsResolved => false;
    }

    private sealed class NullTenantAccessor : IMultiTenantContextAccessor
    {
        public IMultiTenantContext MultiTenantContext { get; } = new NullMultiTenantContext();
    }

    private static IdmtDbContext NewAppContext()
    {
        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseSqlite("Filename=:memory:")
            .Options;
        return new IdmtDbContext(new NullTenantAccessor(), options);
    }

    private static IdmtOpenIddictDbContext NewOpenIddictContext()
    {
        var options = new DbContextOptionsBuilder<IdmtOpenIddictDbContext>()
            .UseSqlite("Filename=:memory:")
            .Options;
        return new IdmtOpenIddictDbContext(options);
    }

    // A resolved tenant, the counterpart to NullTenantAccessor, for exercising save-side stamping.
    private sealed class ResolvedMultiTenantContext : IMultiTenantContext
    {
        public ITenantInfo? TenantInfo { get; init; }
        public StrategyInfo? StrategyInfo { get; init; }
        public bool IsResolved => true;
    }

    private sealed class ResolvedTenantAccessor : IMultiTenantContextAccessor
    {
        public IMultiTenantContext MultiTenantContext { get; } = new ResolvedMultiTenantContext
        {
            TenantInfo = new IdmtTenantInfo { Id = "tenant-a", Identifier = "tenant-a" },
        };
    }

    // A sample consumer-owned tenant-scoped entity, marked multi-tenant in the derived context below.
    private sealed class SampleTenantEntity
    {
        public Guid Id { get; set; }
    }

    // Mirrors how a consumer extends IdmtDbContext: a SQLite-backed derived context that adds its own
    // [MultiTenant] entity. Exercises the protected non-generic DbContextOptions constructor.
    private sealed class ConsumerDbContext : IdmtDbContext
    {
        public ConsumerDbContext(
            IMultiTenantContextAccessor accessor,
            DbContextOptions<ConsumerDbContext> options)
            : base(accessor, options)
        {
        }

        public DbSet<SampleTenantEntity> Samples => Set<SampleTenantEntity>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<SampleTenantEntity>().IsMultiTenant();
        }
    }

    private static ConsumerDbContext NewConsumerContext(IMultiTenantContextAccessor accessor)
    {
        var options = new DbContextOptionsBuilder<ConsumerDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
        return new ConsumerDbContext(accessor, options);
    }

    [Fact]
    public void OpenIddict_token_entity_has_no_TenantId()
    {
        using var db = NewOpenIddictContext();

        var tokenEntity = db.Model.GetEntityTypes()
            .Single(t => t.ClrType.Name.StartsWith("OpenIddictEntityFrameworkCoreToken", StringComparison.Ordinal));

        Assert.Null(tokenEntity.FindProperty("TenantId"));
    }

    [Theory]
    [InlineData(typeof(IdmtUser))]
    [InlineData(typeof(IdentityUserRole<Guid>))]
    [InlineData(typeof(IdentityUserClaim<Guid>))]
    [InlineData(typeof(IdentityUserToken<Guid>))]
    public void Identity_entities_are_de_tenanted(Type clrType)
    {
        using var db = NewAppContext();

        var entity = db.Model.GetEntityTypes().Single(e => e.ClrType == clrType);

        Assert.Null(entity.FindAnnotation("Finbuckle:MultiTenant"));
        Assert.Null(entity.FindProperty("TenantId"));
    }

    [Fact]
    public void Role_keeps_its_explicit_tenant_id_but_is_not_finbuckle_managed()
    {
        using var db = NewAppContext();

        var role = db.Model.GetEntityTypes().Single(e => e.ClrType == typeof(IdmtRole));

        // The Finbuckle stamping is stripped...
        Assert.Null(role.FindAnnotation("Finbuckle:MultiTenant"));

        // ...but the explicit, declared TenantId column survives.
        var tenantId = role.FindProperty("TenantId");
        Assert.NotNull(tenantId);
        Assert.False(tenantId!.IsShadowProperty());
    }

    [Fact]
    public void App_context_exposes_the_access_edges()
    {
        using var db = NewAppContext();

        Assert.NotNull(db.Model.FindEntityType(typeof(TenantAccess)));
        Assert.NotNull(db.Model.FindEntityType(typeof(ClientTenantAccess)));
    }

    [Fact]
    public void Consumer_multitenant_entity_is_finbuckle_managed()
    {
        using var db = NewConsumerContext(new NullTenantAccessor());

        var entity = db.Model.GetEntityTypes().Single(e => e.ClrType == typeof(SampleTenantEntity));

        // A consumer entity marked IsMultiTenant() under the new base IS Finbuckle-managed:
        // it carries the annotation and a TenantId property, proving stamping/filtering survives
        // the base-class swap and that the context is derivable.
        Assert.NotNull(entity.FindAnnotation("Finbuckle:MultiTenant"));
        Assert.NotNull(entity.FindProperty("TenantId"));
    }

    [Fact]
    public async Task Saving_consumer_entity_stamps_tenant_id()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var options = new DbContextOptionsBuilder<ConsumerDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new ConsumerDbContext(new ResolvedTenantAccessor(), options);
        await db.Database.EnsureCreatedAsync();

        var entity = new SampleTenantEntity { Id = Guid.NewGuid() };
        db.Samples.Add(entity);
        await db.SaveChangesAsync();

        // EnforceMultiTenant, wired through the SaveChanges override, stamped the ambient tenant.
        var stamped = db.Entry(entity).Property("TenantId").CurrentValue;
        Assert.Equal("tenant-a", stamped);
    }
}
