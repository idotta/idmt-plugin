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
    private readonly AsyncLocalMultiTenantContextAccessor<IdmtTenantInfo> _accessor;
    private readonly TenantOperationService _service;

    public TenantOperationServiceTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        _accessor = new AsyncLocalMultiTenantContextAccessor<IdmtTenantInfo>();

        var services = new ServiceCollection();
        services.AddSingleton(_tenantStoreMock.Object);
        services.AddSingleton<IMultiTenantContextAccessor>(_accessor);
        services.AddSingleton<IMultiTenantContextAccessor<IdmtTenantInfo>>(_accessor);
        services.AddSingleton<IMultiTenantContextSetter>(_accessor);
        var serviceProvider = services.BuildServiceProvider();

        _service = new TenantOperationService(serviceProvider);
    }

    private static IdmtTenantInfo MakeTenant(string identifier, bool active = true) =>
        new(identifier, identifier, identifier) { IsActive = active };

    private void SetOuterContext(IdmtTenantInfo tenant)
    {
        ((IMultiTenantContextSetter)_accessor).MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);
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
        var tenant = MakeTenant("inactive-tenant", active: false);
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
        var tenant = MakeTenant("inactive-tenant", active: false);
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("inactive-tenant"))
            .ReturnsAsync(tenant);

        var result = await _service.ExecuteInTenantScopeAsync("inactive-tenant",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success),
            requireActive: false);

        Assert.False(result.IsError);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_SetsTargetTenantContext_DuringOperation()
    {
        var tenant = MakeTenant("test-tenant");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("test-tenant"))
            .ReturnsAsync(tenant);

        string? observedIdentifier = null;
        var result = await _service.ExecuteInTenantScopeAsync("test-tenant", _ =>
        {
            observedIdentifier = _accessor.MultiTenantContext.TenantInfo?.Identifier;
            return Task.FromResult<ErrorOr<Success>>(Result.Success);
        });

        Assert.False(result.IsError);
        Assert.Equal("test-tenant", observedIdentifier);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_RestoresPreviousContext_WhenDelegateSucceeds()
    {
        var outer = MakeTenant("outer");
        var target = MakeTenant("target");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("target")).ReturnsAsync(target);
        SetOuterContext(outer);

        var result = await _service.ExecuteInTenantScopeAsync("target",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success));

        Assert.False(result.IsError);
        Assert.Equal("outer", _accessor.MultiTenantContext.TenantInfo?.Identifier);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_RestoresPreviousContext_WhenDelegateThrows()
    {
        var outer = MakeTenant("outer");
        var target = MakeTenant("target");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("target")).ReturnsAsync(target);
        SetOuterContext(outer);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await _service.ExecuteInTenantScopeAsync<Success>("target", _ =>
                throw new InvalidOperationException("boom"));
        });

        Assert.Equal("outer", _accessor.MultiTenantContext.TenantInfo?.Identifier);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_RestoresFromNullPreviousContext()
    {
        var target = MakeTenant("target");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("target")).ReturnsAsync(target);
        // Outer context is the default empty MultiTenantContext — TenantInfo is null.

        var result = await _service.ExecuteInTenantScopeAsync("target",
            _ => Task.FromResult<ErrorOr<Success>>(Result.Success));

        Assert.False(result.IsError);
        Assert.Null(_accessor.MultiTenantContext.TenantInfo);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_RestoresAcrossAsyncBoundary()
    {
        var outer = MakeTenant("outer");
        var target = MakeTenant("target");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("target")).ReturnsAsync(target);
        SetOuterContext(outer);

        var result = await _service.ExecuteInTenantScopeAsync("target", async _ =>
        {
            await Task.Yield();
            await Task.Delay(1);
            return Result.Success;
        });

        Assert.False(result.IsError);
        Assert.Equal("outer", _accessor.MultiTenantContext.TenantInfo?.Identifier);
    }

    [Fact]
    public async Task ExecuteInTenantScopeAsync_NestedCalls_RestoreEachLayer()
    {
        var outer = MakeTenant("tenant-a");
        var middle = MakeTenant("tenant-b");
        var inner = MakeTenant("tenant-c");
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("tenant-b")).ReturnsAsync(middle);
        _tenantStoreMock.Setup(x => x.GetByIdentifierAsync("tenant-c")).ReturnsAsync(inner);
        SetOuterContext(outer);

        string? betweenNested = null;

        var result = await _service.ExecuteInTenantScopeAsync("tenant-b", async _ =>
        {
            Assert.Equal("tenant-b", _accessor.MultiTenantContext.TenantInfo?.Identifier);

            await _service.ExecuteInTenantScopeAsync("tenant-c",
                __ => Task.FromResult<ErrorOr<Success>>(Result.Success));

            betweenNested = _accessor.MultiTenantContext.TenantInfo?.Identifier;
            return Result.Success;
        });

        Assert.False(result.IsError);
        Assert.Equal("tenant-b", betweenNested);
        Assert.Equal("tenant-a", _accessor.MultiTenantContext.TenantInfo?.Identifier);
    }
}
