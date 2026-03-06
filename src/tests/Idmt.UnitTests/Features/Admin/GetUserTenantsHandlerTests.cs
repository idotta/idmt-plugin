using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class GetUserTenantsHandlerTests : IDisposable
{
    private readonly IdmtDbContext _dbContext;
    private readonly FakeTimeProvider _timeProvider;
    private readonly GetUserTenants.GetUserTenantsHandler _handler;

    public GetUserTenantsHandlerTests()
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

        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 3, 4, 12, 0, 0, TimeSpan.Zero));

        _handler = new GetUserTenants.GetUserTenantsHandler(
            _dbContext,
            _timeProvider,
            NullLogger<GetUserTenants.GetUserTenantsHandler>.Instance);
    }

    [Fact]
    public async Task ExcludesExpiredAccess_FromResults()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "tenant-1";

        // Seed a tenant
        _dbContext.Set<IdmtTenantInfo>().Add(
            new IdmtTenantInfo(tenantId, "active-tenant", "Active Tenant"));

        // Seed an expired access record
        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = tenantId,
            IsActive = true,
            ExpiresAt = new DateTime(2026, 3, 3, 0, 0, 0, DateTimeKind.Utc) // yesterday
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(userId, 1, 10);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(0, result.Value.TotalCount);
    }

    [Fact]
    public async Task ExcludesInactiveAccess_FromResults()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "tenant-2";

        _dbContext.Set<IdmtTenantInfo>().Add(
            new IdmtTenantInfo(tenantId, "some-tenant", "Some Tenant"));

        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = tenantId,
            IsActive = false,
            ExpiresAt = null
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(userId, 1, 10);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(0, result.Value.TotalCount);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
