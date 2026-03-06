using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Health;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Health;

public class BasicHealthCheckTests
{
    private readonly Mock<TimeProvider> _timeProviderMock;
    private readonly DateTimeOffset _fixedTime = new(2026, 3, 4, 12, 0, 0, TimeSpan.Zero);

    public BasicHealthCheckTests()
    {
        _timeProviderMock = new Mock<TimeProvider>();
        _timeProviderMock.Setup(x => x.GetUtcNow()).Returns(_fixedTime);
    }

    [Fact]
    public async Task ReturnsUnhealthy_WhenDatabaseCannotConnect()
    {
        // Arrange - use a provider that won't actually connect
        var dbContext = CreateDbContextWithCanConnect(false);
        var healthCheck = new BasicHealthCheck(dbContext, _timeProviderMock.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(
            new HealthCheckContext(), CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Database connection failed", result.Description);
        Assert.NotNull(result.Data);
        Assert.Equal(false, result.Data["database_connected"]);
        Assert.Equal(_fixedTime.UtcDateTime, result.Data["timestamp"]);
    }

    [Fact]
    public async Task ReturnsUnhealthy_WhenExceptionThrown()
    {
        // Arrange - use a context that throws on CanConnectAsync
        var dbContext = CreateDbContextThatThrows(new InvalidOperationException("Connection refused"));
        var healthCheck = new BasicHealthCheck(dbContext, _timeProviderMock.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(
            new HealthCheckContext(), CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Database is unhealthy", result.Description);
        Assert.NotNull(result.Exception);
        Assert.IsType<InvalidOperationException>(result.Exception);
        Assert.Equal("Connection refused", result.Exception.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(_fixedTime.UtcDateTime, result.Data["timestamp"]);
    }

    [Fact]
    public async Task ReturnsHealthy_WithExpectedData()
    {
        // Arrange - use InMemory which will successfully "connect"
        var dbContext = CreateDbContextWithCanConnect(true);
        var healthCheck = new BasicHealthCheck(dbContext, _timeProviderMock.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(
            new HealthCheckContext(), CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("Database is healthy", result.Description);
        Assert.NotNull(result.Data);
        Assert.Equal(true, result.Data["database_connected"]);
        Assert.Equal(_fixedTime.UtcDateTime, result.Data["timestamp"]);
    }

    private IdmtDbContext CreateDbContextWithCanConnect(bool canConnect)
    {
        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        if (canConnect)
        {
            // InMemory database will return true for CanConnectAsync
            var options = new DbContextOptionsBuilder<IdmtDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            return new IdmtDbContext(
                tenantAccessorMock.Object,
                options,
                currentUserServiceMock.Object,
                TimeProvider.System,
                NullLogger<IdmtDbContext>.Instance);
        }
        else
        {
            // Use a connection string that will fail - SQLite with invalid path
            var options = new DbContextOptionsBuilder<IdmtDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            var dbContext = new Mock<IdmtDbContext>(
                tenantAccessorMock.Object,
                options,
                currentUserServiceMock.Object,
                TimeProvider.System,
                NullLogger<IdmtDbContext>.Instance)
            { CallBase = true };

            var databaseMock = new Mock<DatabaseFacade>(dbContext.Object);
            databaseMock
                .Setup(d => d.CanConnectAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
            dbContext.SetupGet(x => x.Database).Returns(databaseMock.Object);

            return dbContext.Object;
        }
    }

    private IdmtDbContext CreateDbContextThatThrows(Exception exception)
    {
        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        var dbContext = new Mock<IdmtDbContext>(
            tenantAccessorMock.Object,
            options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance)
        { CallBase = true };

        var databaseMock = new Mock<DatabaseFacade>(dbContext.Object);
        databaseMock
            .Setup(d => d.CanConnectAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);
        dbContext.SetupGet(x => x.Database).Returns(databaseMock.Object);

        return dbContext.Object;
    }
}
