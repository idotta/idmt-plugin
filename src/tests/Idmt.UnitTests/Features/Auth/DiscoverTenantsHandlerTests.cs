using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class DiscoverTenantsHandlerTests : IDisposable
{
    private readonly IdmtDbContext _dbContext;
    private readonly FakeTimeProvider _timeProvider;
    private readonly DiscoverTenants.DiscoverTenantsHandler _handler;

    public DiscoverTenantsHandlerTests()
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

        // Allow seeding users with any TenantId regardless of current context
        _dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;

        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 3, 6, 12, 0, 0, TimeSpan.Zero));

        _handler = new DiscoverTenants.DiscoverTenantsHandler(
            _dbContext,
            _timeProvider,
            NullLogger<DiscoverTenants.DiscoverTenantsHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsEmptyArray_WhenNoUserMatches()
    {
        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("unknown@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Empty(result.Value.Tenants);
    }

    [Fact]
    public async Task ReturnsTenant_WhenUserExistsInOneTenant()
    {
        // Arrange
        var tenantId = Guid.CreateVersion7().ToString();
        _dbContext.Set<IdmtTenantInfo>().Add(
            new IdmtTenantInfo(tenantId, "acme-corp", "Acme Corp"));

        _dbContext.Users.Add(new IdmtUser
        {
            UserName = "alice",
            Email = "alice@test.com",
            NormalizedEmail = "ALICE@TEST.COM",
            IsActive = true,
            TenantId = tenantId
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("alice@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Single(result.Value.Tenants);
        Assert.Equal("acme-corp", result.Value.Tenants[0].Identifier);
        Assert.Equal("Acme Corp", result.Value.Tenants[0].Name);
    }

    [Fact]
    public async Task ExcludesInactiveUsers()
    {
        // Arrange
        var tenantId = Guid.CreateVersion7().ToString();
        _dbContext.Set<IdmtTenantInfo>().Add(
            new IdmtTenantInfo(tenantId, "active-tenant", "Active Tenant"));

        _dbContext.Users.Add(new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            NormalizedEmail = "INACTIVE@TEST.COM",
            IsActive = false,
            TenantId = tenantId
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("inactive@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Empty(result.Value.Tenants);
    }

    [Fact]
    public async Task ExcludesInactiveTenants()
    {
        // Arrange
        var tenantId = Guid.CreateVersion7().ToString();
        _dbContext.Set<IdmtTenantInfo>().Add(
            new IdmtTenantInfo(tenantId, "dead-tenant", "Dead Tenant") { IsActive = false });

        _dbContext.Users.Add(new IdmtUser
        {
            UserName = "bob",
            Email = "bob@test.com",
            NormalizedEmail = "BOB@TEST.COM",
            IsActive = true,
            TenantId = tenantId
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("bob@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Empty(result.Value.Tenants);
    }

    [Fact]
    public async Task IncludesTenantAccessGrants()
    {
        // Arrange
        var homeTenantId = Guid.CreateVersion7().ToString();
        var grantedTenantId = Guid.CreateVersion7().ToString();
        var userId = Guid.NewGuid();

        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo(homeTenantId, "home-tenant", "Home Tenant"),
            new IdmtTenantInfo(grantedTenantId, "granted-tenant", "Granted Tenant"));

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "charlie",
            Email = "charlie@test.com",
            NormalizedEmail = "CHARLIE@TEST.COM",
            IsActive = true,
            TenantId = homeTenantId
        });

        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = grantedTenantId,
            IsActive = true,
            ExpiresAt = null
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("charlie@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(2, result.Value.Tenants.Count);
        Assert.Contains(result.Value.Tenants, t => t.Identifier == "home-tenant");
        Assert.Contains(result.Value.Tenants, t => t.Identifier == "granted-tenant");
    }

    [Fact]
    public async Task ExcludesExpiredTenantAccessGrants()
    {
        // Arrange
        var homeTenantId = Guid.CreateVersion7().ToString();
        var expiredTenantId = Guid.CreateVersion7().ToString();
        var userId = Guid.NewGuid();

        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo(homeTenantId, "home-tenant", "Home Tenant"),
            new IdmtTenantInfo(expiredTenantId, "expired-tenant", "Expired Tenant"));

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "dave",
            Email = "dave@test.com",
            NormalizedEmail = "DAVE@TEST.COM",
            IsActive = true,
            TenantId = homeTenantId
        });

        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = expiredTenantId,
            IsActive = true,
            ExpiresAt = new DateTime(2026, 3, 5, 0, 0, 0, DateTimeKind.Utc) // yesterday
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("dave@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Single(result.Value.Tenants);
        Assert.Equal("home-tenant", result.Value.Tenants[0].Identifier);
    }

    [Fact]
    public async Task ExcludesInactiveTenantAccessGrants()
    {
        // Arrange
        var homeTenantId = Guid.CreateVersion7().ToString();
        var revokedTenantId = Guid.CreateVersion7().ToString();
        var userId = Guid.NewGuid();

        _dbContext.Set<IdmtTenantInfo>().AddRange(
            new IdmtTenantInfo(homeTenantId, "home-tenant", "Home Tenant"),
            new IdmtTenantInfo(revokedTenantId, "revoked-tenant", "Revoked Tenant"));

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "eve",
            Email = "eve@test.com",
            NormalizedEmail = "EVE@TEST.COM",
            IsActive = true,
            TenantId = homeTenantId
        });

        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = revokedTenantId,
            IsActive = false,
            ExpiresAt = null
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("eve@test.com"));

        // Assert
        Assert.False(result.IsError);
        Assert.Single(result.Value.Tenants);
        Assert.Equal("home-tenant", result.Value.Tenants[0].Identifier);
    }

    [Fact]
    public async Task ReturnsUnexpectedError_WhenExceptionOccurs()
    {
        // Arrange — dispose the context to force an exception
        _dbContext.Dispose();

        // Act
        var result = await _handler.HandleAsync(
            new DiscoverTenants.DiscoverTenantsRequest("test@test.com"));

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("General.Unexpected", result.FirstError.Code);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
