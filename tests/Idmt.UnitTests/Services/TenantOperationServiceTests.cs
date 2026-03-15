using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Idmt.UnitTests.Services;

public class TenantOperationServiceTests
{
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<IMultiTenantContextSetter> _tenantContextSetterMock;
    private readonly TenantOperationService _service;

    public TenantOperationServiceTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        _tenantContextSetterMock = new Mock<IMultiTenantContextSetter>();

        var services = new ServiceCollection();
        services.AddSingleton(_tenantStoreMock.Object);
        services.AddSingleton(_tenantContextSetterMock.Object);
        var serviceProvider = services.BuildServiceProvider();

        _service = new TenantOperationService(serviceProvider);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_ReturnsTenantNotFound_WhenTenantDoesNotExist()
    {
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("nonexistent"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        var result = await _service.ExecuteInTenantScopeAsync("nonexistent",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success));

        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_ReturnsTenantInactive_WhenRequireActiveAndTenantInactive()
    {
        var tenant = new IdmtTenantInfo("inactive-tenant", "inactive-tenant", "Inactive") { IsActive = false };
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("inactive-tenant"))
            .ReturnsAsync(tenant);

        var result = await _service.ExecuteInTenantScopeAsync("inactive-tenant",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success),
            requireActive: true);

        Assert.True(result.IsError);
        Assert.Equal("Tenant.Inactive", result.FirstError.Code);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_AllowsExecution_WhenRequireActiveFalseAndTenantInactive()
    {
        var tenant = new IdmtTenantInfo("inactive-tenant", "inactive-tenant", "Inactive") { IsActive = false };
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("inactive-tenant"))
            .ReturnsAsync(tenant);

        var result = await _service.ExecuteInTenantScopeAsync("inactive-tenant",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success),
            requireActive: false);

        Assert.False(result.IsError);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_SetsTenantContext_BeforeCallingOperation()
    {
        var tenant = new IdmtTenantInfo("test-tenant", "test-tenant", "Test") { IsActive = true };
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("test-tenant"))
            .ReturnsAsync(tenant);

        IMultiTenantContext? capturedContext = null;
        _tenantContextSetterMock.SetupSet(x => x.MultiTenantContext = It.IsAny<IMultiTenantContext>())
            .Callback<IMultiTenantContext>(ctx => capturedContext = ctx);

        var result = await _service.ExecuteInTenantScopeAsync("test-tenant",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success));

        Assert.False(result.IsError);
        Assert.NotNull(capturedContext);
        Assert.Equal("test-tenant", capturedContext!.TenantInfo?.Identifier);
    }
}
