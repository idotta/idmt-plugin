using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class GetAllTenantsHandlerTests : IDisposable
{
    private readonly IdmtDbContext _dbContext;
    private readonly GetAllTenants.GetAllTenantsHandler _handler;

    public GetAllTenantsHandlerTests()
    {
        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();

        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _handler = new GetAllTenants.GetAllTenantsHandler(
            _dbContext,
            NullLogger<GetAllTenants.GetAllTenantsHandler>.Instance);
    }

    [Fact]
    public async Task ExcludesDefaultTenant_FromResults()
    {
        // Arrange
        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo("id1", MultiTenantOptions.DefaultTenantIdentifier, "System Tenant"),
            new IdmtTenantInfo("id2", "tenant-a", "Tenant A"),
            new IdmtTenantInfo("id3", "tenant-b", "Tenant B"));
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(page: 1, pageSize: 100);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(2, result.Value.TotalCount);
        Assert.DoesNotContain(result.Value.Items, t => t.Identifier == MultiTenantOptions.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task ReturnsTenantsOrderedByName()
    {
        // Arrange
        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo("id1", "tenant-z", "Zebra Corp"),
            new IdmtTenantInfo("id2", "tenant-a", "Alpha Inc"),
            new IdmtTenantInfo("id3", "tenant-m", "Midway LLC"));
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(page: 1, pageSize: 100);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(3, result.Value.TotalCount);
        Assert.Equal("Alpha Inc", result.Value.Items[0].Name);
        Assert.Equal("Midway LLC", result.Value.Items[1].Name);
        Assert.Equal("Zebra Corp", result.Value.Items[2].Name);
    }

    [Fact]
    public async Task Pagination_ReturnsCorrectPage_AndHasMore()
    {
        // Arrange — seed 5 tenants (names chosen so ordering is predictable: A–E)
        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo("id1", "tenant-a", "Tenant A"),
            new IdmtTenantInfo("id2", "tenant-b", "Tenant B"),
            new IdmtTenantInfo("id3", "tenant-c", "Tenant C"),
            new IdmtTenantInfo("id4", "tenant-d", "Tenant D"),
            new IdmtTenantInfo("id5", "tenant-e", "Tenant E"));
        await _dbContext.SaveChangesAsync();

        // Act — request page 2 with page size 2
        var result = await _handler.HandleAsync(page: 2, pageSize: 2);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(5, result.Value.TotalCount);
        Assert.Equal(2, result.Value.Items.Count);
        Assert.Equal("Tenant C", result.Value.Items[0].Name); // 3rd overall
        Assert.Equal("Tenant D", result.Value.Items[1].Name); // 4th overall
        Assert.True(result.Value.HasMore);                    // "Tenant E" remains
    }

    [Fact]
    public async Task LastPage_HasMore_IsFalse()
    {
        // Arrange
        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo("id1", "tenant-a", "Tenant A"),
            new IdmtTenantInfo("id2", "tenant-b", "Tenant B"),
            new IdmtTenantInfo("id3", "tenant-c", "Tenant C"));
        await _dbContext.SaveChangesAsync();

        // Act — page size exactly matches total count
        var result = await _handler.HandleAsync(page: 1, pageSize: 3);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(3, result.Value.TotalCount);
        Assert.Equal(3, result.Value.Items.Count);
        Assert.False(result.Value.HasMore);
    }

    [Fact]
    public async Task EmptyStore_ReturnsEmptyPage()
    {
        // No data seeded.

        var result = await _handler.HandleAsync(page: 1, pageSize: 25);

        Assert.False(result.IsError);
        Assert.Equal(0, result.Value.TotalCount);
        Assert.Empty(result.Value.Items);
        Assert.False(result.Value.HasMore);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
