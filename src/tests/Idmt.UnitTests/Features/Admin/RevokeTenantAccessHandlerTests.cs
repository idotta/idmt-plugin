using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class RevokeTenantAccessHandlerTests : IDisposable
{
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly IdmtDbContext _dbContext;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly RevokeTenantAccess.RevokeTenantAccessHandler _handler;

    public RevokeTenantAccessHandlerTests()
    {
        _tenantOpsMock = new Mock<ITenantOperationService>();

        // InMemory DbContext
        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var dbOptions = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            dbOptions,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        _handler = new RevokeTenantAccess.RevokeTenantAccessHandler(
            _dbContext,
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
            NullLogger<RevokeTenantAccess.RevokeTenantAccessHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsAccessNotFound_WhenNoAccessRecord()
    {
        // Arrange
        var userId = Guid.NewGuid();

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "testuser",
            Email = "test@test.com",
            TenantId = "sys-id"
        });
        await _dbContext.SaveChangesAsync();

        var tenant = new IdmtTenantInfo("tid", "target-tenant", "Target");
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("target-tenant"))
            .ReturnsAsync(tenant);

        // No access record seeded

        // Act
        var result = await _handler.HandleAsync(userId, "target-tenant");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.AccessNotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task SucceedsGracefully_WhenUserNotInTenantScope()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "tid";

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "scopeuser",
            Email = "scope@test.com",
            TenantId = "sys-id"
        });

        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = tenantId,
            IsActive = true
        });
        await _dbContext.SaveChangesAsync();

        var tenant = new IdmtTenantInfo(tenantId, "target-tenant", "Target");
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("target-tenant"))
            .ReturnsAsync(tenant);

        // ExecuteInTenantScopeAsync succeeds (user not found in tenant scope is handled gracefully
        // in the handler by returning Result.Success when targetUser is null)
        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                "target-tenant",
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                false))
            .ReturnsAsync(Result.Success);

        // Act
        var result = await _handler.HandleAsync(userId, "target-tenant");

        // Assert
        Assert.False(result.IsError);

        // Verify the access record was deactivated
        var access = await _dbContext.TenantAccess
            .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);

        Assert.NotNull(access);
        Assert.False(access.IsActive);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
