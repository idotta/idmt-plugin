using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Moq;

namespace Idmt.UnitTests.Services;

public class TenantAccessServiceTests
{
    private readonly Mock<IMultiTenantContextAccessor> _tenantAccessorMock;
    private readonly Mock<ITenantResolver<IdmtTenantInfo>> _tenantResolverMock;
    private readonly Mock<IMultiTenantContextSetter> _tenantContextSetterMock;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly IdmtDbContext _dbContext;
    private readonly TenantAccessService _service;

    public TenantAccessServiceTests()
    {
        _tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _tenantResolverMock = new Mock<ITenantResolver<IdmtTenantInfo>>();
        _tenantContextSetterMock = new Mock<IMultiTenantContextSetter>();
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        _currentUserServiceMock = new Mock<ICurrentUserService>();

        // Setup mock to return a context, even if empty, to avoid NRE in base constructor if it accesses it
        var dummyTenant = new IdmtTenantInfo("system-test-tenant", "system-test", "System Test Tenant");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new IdmtDbContext(
            _tenantAccessorMock.Object,
            options,
            _currentUserServiceMock.Object);

        _service = new TenantAccessService(
            _dbContext,
            _tenantAccessorMock.Object,
            _tenantResolverMock.Object,
            _tenantContextSetterMock.Object,
            _tenantStoreMock.Object,
            _currentUserServiceMock.Object);
    }

    [Fact]
    public async Task GetUserAccessibleTenantsAsync_ReturnsTenants_WhenUserHasAccess()
    {
        var userId = Guid.NewGuid();
        var tenantId1 = "tenant1";
        var tenantId2 = "tenant2";

        _dbContext.TenantAccess.AddRange(
            new TenantAccess { UserId = userId, TenantId = tenantId1, IsActive = true },
            new TenantAccess { UserId = userId, TenantId = tenantId2, IsActive = true }
        );
        await _dbContext.SaveChangesAsync();

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId1))
            .ReturnsAsync(new IdmtTenantInfo(tenantId1, tenantId1, "Tenant 1"));
        _tenantStoreMock.Setup(x => x.GetAsync(tenantId2))
            .ReturnsAsync(new IdmtTenantInfo(tenantId2, tenantId2, "Tenant 2"));

        var result = await _service.GetUserAccessibleTenantsAsync(userId);

        Assert.Equal(2, result.Length);
        Assert.Contains(result, t => t.Id == tenantId1);
        Assert.Contains(result, t => t.Id == tenantId2);
    }

    [Fact]
    public async Task GetUserAccessibleTenantsAsync_IgnoresInactiveAccess()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        _dbContext.TenantAccess.Add(
            new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = false }
        );
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetUserAccessibleTenantsAsync(userId);

        Assert.Empty(result);
    }

    [Fact]
    public async Task CanAccessTenantAsync_ReturnsTrue_WhenAccessExistsAndIsActive()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        _dbContext.TenantAccess.Add(
            new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = true }
        );
        await _dbContext.SaveChangesAsync();

        var result = await _service.CanAccessTenantAsync(userId, tenantId);

        Assert.True(result);
    }

    [Fact]
    public async Task CanAccessTenantAsync_ReturnsFalse_WhenAccessIsInactive()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        _dbContext.TenantAccess.Add(
            new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = false }
        );
        await _dbContext.SaveChangesAsync();

        var result = await _service.CanAccessTenantAsync(userId, tenantId);

        Assert.False(result);
    }

    [Fact]
    public async Task CanAccessTenantAsync_ReturnsFalse_WhenAccessExpired()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        _dbContext.TenantAccess.Add(
            new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = true, ExpiresAt = DateTime.UtcNow.AddDays(-1) }
        );
        await _dbContext.SaveChangesAsync();

        var result = await _service.CanAccessTenantAsync(userId, tenantId);

        Assert.False(result);
    }

    [Fact]
    public async Task GrantTenantAccessAsync_CreatesNewAccess_WhenNoneExists()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        // Setup user
        var user = new IdmtUser { Id = userId, UserName = "testuser", Email = "test@example.com" };
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        // Setup tenant resolver
        var tenant = new IdmtTenantInfo(tenantId, tenantId, "Test Tenant");
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);

        _tenantResolverMock.Setup(x => x.ResolveAsync(tenantId))
            .ReturnsAsync(context);

        // Mock current tenant context for restoration
        var currentTenant = new IdmtTenantInfo("current", "current", "Current Tenant");
        var currentTenantContext = new MultiTenantContext<IdmtTenantInfo>(currentTenant);
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(currentTenantContext);

        var result = await _service.GrantTenantAccessAsync(userId, tenantId);

        Assert.True(result);
        var access = await _dbContext.TenantAccess.FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);
        Assert.NotNull(access);
        Assert.True(access.IsActive);
    }

    [Fact]
    public async Task GrantTenantAccessAsync_UpdatesExistingAccess()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        // Setup user and existing inactive access
        var user = new IdmtUser { Id = userId, UserName = "testuser", Email = "test@example.com" };
        _dbContext.Users.Add(user);
        _dbContext.TenantAccess.Add(new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = false });
        await _dbContext.SaveChangesAsync();

        var tenant = new IdmtTenantInfo(tenantId, tenantId, "Test Tenant");
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);

        _tenantResolverMock.Setup(x => x.ResolveAsync(tenantId))
            .ReturnsAsync(context);

        var currentTenant = new IdmtTenantInfo("current", "current", "Current Tenant");
        var currentTenantContext = new MultiTenantContext<IdmtTenantInfo>(currentTenant);
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(currentTenantContext);

        var result = await _service.GrantTenantAccessAsync(userId, tenantId);

        Assert.True(result);
        var access = await _dbContext.TenantAccess.FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);
        Assert.NotNull(access);
        Assert.True(access.IsActive);
    }

    [Fact]
    public async Task GrantTenantAccessAsync_ReturnsFalse_WhenUserNotFound()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        var result = await _service.GrantTenantAccessAsync(userId, tenantId);

        Assert.False(result);
    }

    [Fact]
    public async Task RevokeTenantAccessAsync_DeactivatesAccess()
    {
        var userId = Guid.NewGuid();
        var tenantId = "tenant1";

        // Setup user and existing active access
        var user = new IdmtUser { Id = userId, UserName = "testuser", Email = "test@example.com" };
        _dbContext.Users.Add(user);
        _dbContext.TenantAccess.Add(new TenantAccess { UserId = userId, TenantId = tenantId, IsActive = true });
        await _dbContext.SaveChangesAsync();

        var tenant = new IdmtTenantInfo(tenantId, tenantId, "Test Tenant");
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);

        _tenantResolverMock.Setup(x => x.ResolveAsync(tenantId))
            .ReturnsAsync(context);

        var currentTenant = new IdmtTenantInfo("current", "current", "Current Tenant");
        var currentTenantContext = new MultiTenantContext<IdmtTenantInfo>(currentTenant);
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(currentTenantContext);

        var result = await _service.RevokeTenantAccessAsync(userId, tenantId);

        Assert.True(result);
        var access = await _dbContext.TenantAccess.FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);
        Assert.NotNull(access);
        Assert.False(access.IsActive);
    }

    [Theory]
    [InlineData(IdmtDefaultRoleTypes.SysSupport, IdmtDefaultRoleTypes.SysAdmin, false)]
    [InlineData(IdmtDefaultRoleTypes.SysSupport, IdmtDefaultRoleTypes.TenantAdmin, true)]
    [InlineData(IdmtDefaultRoleTypes.TenantAdmin, IdmtDefaultRoleTypes.SysAdmin, false)]
    [InlineData(IdmtDefaultRoleTypes.TenantAdmin, IdmtDefaultRoleTypes.SysSupport, false)]
    [InlineData(IdmtDefaultRoleTypes.TenantAdmin, "TenantUser", true)]
    [InlineData("TenantUser", IdmtDefaultRoleTypes.SysAdmin, false)]
    public void CanAssignRole_ValidatesRoleHierarchy(string currentUserRole, string targetRole, bool expected)
    {
        // Reset mocks
        _currentUserServiceMock.Reset();

        // Setup initial assumption: user is in the role we're testing
        _currentUserServiceMock.Setup(x => x.IsInRole(currentUserRole)).Returns(true);

        var result = _service.CanAssignRole(targetRole);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void CanManageUser_ReturnsFalse_WhenSysSupportManagesSysAdmin()
    {
        _currentUserServiceMock.Setup(x => x.IsInRole(IdmtDefaultRoleTypes.SysSupport)).Returns(true);

        var result = _service.CanManageUser([IdmtDefaultRoleTypes.SysAdmin]);

        Assert.False(result);
    }

    [Fact]
    public void CanManageUser_ReturnsFalse_WhenTenantAdminManagesSysAdmin()
    {
        _currentUserServiceMock.Setup(x => x.IsInRole(IdmtDefaultRoleTypes.TenantAdmin)).Returns(true);

        var result = _service.CanManageUser([IdmtDefaultRoleTypes.SysAdmin]);

        Assert.False(result);
    }

    [Fact]
    public void CanManageUser_ReturnsTrue_WhenSysSupportManagesTenantAdmin()
    {
        _currentUserServiceMock.Setup(x => x.IsInRole(IdmtDefaultRoleTypes.SysSupport)).Returns(true);

        var result = _service.CanManageUser([IdmtDefaultRoleTypes.TenantAdmin]);

        Assert.True(result);
    }
}
