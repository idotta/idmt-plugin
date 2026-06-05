using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Persistence;

/// <summary>
/// Phase 1 (canonical identity) model assertions for <see cref="IdmtDbContext"/>:
/// IdmtUser is a global entity (no Finbuckle multi-tenant filter) and carries a global
/// unique index on NormalizedEmail.
/// </summary>
public class IdmtDbContextTests
{
    private static IdmtDbContext CreateContext()
    {
        var tenantAccessor = new Mock<IMultiTenantContextAccessor>();
        var dummyTenant = new IdmtTenantInfo("system-test-tenant", "system-test", "System Test Tenant");
        tenantAccessor.SetupGet(x => x.MultiTenantContext)
            .Returns(new MultiTenantContext<IdmtTenantInfo>(dummyTenant));

        var currentUser = new Mock<ICurrentUserService>();

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        return new IdmtDbContext(
            tenantAccessor.Object,
            options,
            currentUser.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);
    }

    [Fact]
    public void OnModelCreating_IdmtUser_NotMultiTenant()
    {
        // Arrange
        using var context = CreateContext();
        var entityType = context.Model.FindEntityType(typeof(IdmtUser));
        Assert.NotNull(entityType);

        // Act + Assert: Finbuckle stamps every multi-tenant entity with a "multiTenant" annotation
        // (`Finbuckle.MultiTenant.Annotations.MultiTenant`). Phase 1 made IdmtUser a global entity,
        // so no such annotation should be present.
        var annotations = entityType!.GetAnnotations()
            .Where(a => a.Name.Contains("multiTenant", StringComparison.OrdinalIgnoreCase)
                        || a.Name.Contains("MultiTenant", StringComparison.Ordinal))
            .ToList();
        Assert.Empty(annotations);

        // Belt-and-suspenders: ensure the entity does not declare a tenant-scoped query filter on
        // a TenantId shadow property.
        var tenantIdProperty = entityType.FindProperty("TenantId");
        Assert.Null(tenantIdProperty);
    }

    [Fact]
    public void OnModelCreating_IdmtUser_HasNormalizedEmailUniqueIndex()
    {
        // Arrange
        using var context = CreateContext();
        var entityType = context.Model.FindEntityType(typeof(IdmtUser));
        Assert.NotNull(entityType);

        // Act
        var indexes = entityType!.GetIndexes().ToList();
        var normalizedEmailIndex = indexes.FirstOrDefault(ix =>
            ix.Properties.Count == 1 &&
            string.Equals(ix.Properties[0].Name, nameof(IdmtUser.NormalizedEmail), StringComparison.Ordinal));

        // Assert
        Assert.NotNull(normalizedEmailIndex);
        Assert.True(normalizedEmailIndex!.IsUnique,
            "Phase 1 requires NormalizedEmail to be globally unique.");
    }

    [Fact]
    public void OnModelCreating_IdmtUser_DoesNotHaveLegacyEmailUserNameTenantIdIndex()
    {
        // Arrange
        using var context = CreateContext();
        var entityType = context.Model.FindEntityType(typeof(IdmtUser));
        Assert.NotNull(entityType);

        // Act + Assert: legacy unique index on (Email, UserName, TenantId) must be gone.
        var legacy = entityType!.GetIndexes()
            .FirstOrDefault(ix => ix.Properties.Any(p =>
                string.Equals(p.Name, "TenantId", StringComparison.Ordinal)));
        Assert.Null(legacy);
    }
}
