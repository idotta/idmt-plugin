using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class DeleteTenantHandlerTests
{
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly DeleteTenant.DeleteTenantHandler _handler;

    public DeleteTenantHandlerTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        _handler = new DeleteTenant.DeleteTenantHandler(
            _tenantStoreMock.Object,
            NullLogger<DeleteTenant.DeleteTenantHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsCannotDeleteDefault_WhenDeletingDefaultTenant()
    {
        // Act
        var result = await _handler.HandleAsync(MultiTenantOptions.DefaultTenantIdentifier);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.CannotDeleteDefault", result.FirstError.Code);

        // Store should never be called
        _tenantStoreMock.Verify(x => x.GetByIdentifierAsync(It.IsAny<string>()), Times.Never);
    }

    [Theory]
    [InlineData("System-Tenant")]
    [InlineData("SYSTEM-TENANT")]
    [InlineData("system-TENANT")]
    [InlineData("System-tenant")]
    public async Task ReturnsCannotDeleteDefault_ForCaseVariants(string identifier)
    {
        // Act
        var result = await _handler.HandleAsync(identifier);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.CannotDeleteDefault", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenTenantDoesNotExist()
    {
        // Arrange
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("nonexistent"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        // Act
        var result = await _handler.HandleAsync("nonexistent");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsDeletionFailed_WhenUpdateFails()
    {
        // Arrange
        var tenant = new IdmtTenantInfo("tid", "my-tenant", "My Tenant") { IsActive = true };

        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("my-tenant"))
            .ReturnsAsync(tenant);

        _tenantStoreMock
            .Setup(x => x.UpdateAsync(It.Is<IdmtTenantInfo>(t => !t.IsActive)))
            .ReturnsAsync(false);

        // Act
        var result = await _handler.HandleAsync("my-tenant");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.DeletionFailed", result.FirstError.Code);
    }
}
