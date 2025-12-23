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
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly IdmtDbContext _dbContext;
    private readonly TenantAccessService _service;

    public TenantAccessServiceTests()
    {
        _tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
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
            _currentUserServiceMock.Object);
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
