using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class GetAllTenantsHandlerTests
{
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly GetAllTenants.GetAllTenantsHandler _handler;

    public GetAllTenantsHandlerTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        _handler = new GetAllTenants.GetAllTenantsHandler(
            _tenantStoreMock.Object,
            NullLogger<GetAllTenants.GetAllTenantsHandler>.Instance);
    }

    [Fact]
    public async Task ExcludesDefaultTenant_FromResults()
    {
        // Arrange
        var tenants = new[]
        {
            new IdmtTenantInfo("id1", MultiTenantOptions.DefaultTenantIdentifier, "System Tenant"),
            new IdmtTenantInfo("id2", "tenant-a", "Tenant A"),
            new IdmtTenantInfo("id3", "tenant-b", "Tenant B")
        };

        _tenantStoreMock
            .Setup(x => x.GetAllAsync())
            .ReturnsAsync(tenants);

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
        var tenants = new[]
        {
            new IdmtTenantInfo("id1", "tenant-z", "Zebra Corp"),
            new IdmtTenantInfo("id2", "tenant-a", "Alpha Inc"),
            new IdmtTenantInfo("id3", "tenant-m", "Midway LLC")
        };

        _tenantStoreMock
            .Setup(x => x.GetAllAsync())
            .ReturnsAsync(tenants);

        // Act
        var result = await _handler.HandleAsync(page: 1, pageSize: 100);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(3, result.Value.TotalCount);
        Assert.Equal("Alpha Inc", result.Value.Items[0].Name);
        Assert.Equal("Midway LLC", result.Value.Items[1].Name);
        Assert.Equal("Zebra Corp", result.Value.Items[2].Name);
    }
}
