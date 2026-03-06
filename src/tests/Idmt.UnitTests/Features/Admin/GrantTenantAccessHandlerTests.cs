using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class GrantTenantAccessHandlerTests : IDisposable
{
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly FakeTimeProvider _timeProvider;
    private readonly IdmtDbContext _dbContext;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly GrantTenantAccess.GrantTenantAccessHandler _handler;

    public GrantTenantAccessHandlerTests()
    {
        _tenantOpsMock = new Mock<ITenantOperationService>();
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 3, 4, 12, 0, 0, TimeSpan.Zero));

        // Set up InMemory DbContext
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

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        // Issue 19 fix: inject dependencies directly — no IServiceProvider wrapper required.
        _handler = new GrantTenantAccess.GrantTenantAccessHandler(
            _dbContext,
            _userManagerMock.Object,
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
            _timeProvider,
            NullLogger<GrantTenantAccess.GrantTenantAccessHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsValidationError_WhenExpiresAtIsInPast()
    {
        // Arrange - time is 2026-03-04 12:00 UTC; expiration is yesterday
        var pastDate = new DateTimeOffset(2026, 3, 3, 0, 0, 0, TimeSpan.Zero);

        // Act
        var result = await _handler.HandleAsync(Guid.NewGuid(), "some-tenant", pastDate);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        Assert.Equal("ExpiresAt", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsValidationError_WhenExpiresAtEqualsNow()
    {
        // Arrange - exactly the current time (boundary: <= means equal is rejected)
        var exactNow = _timeProvider.GetUtcNow();

        // Act
        var result = await _handler.HandleAsync(Guid.NewGuid(), "some-tenant", exactNow);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        Assert.Equal("ExpiresAt", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUserNotFound_WhenUserDoesNotExist()
    {
        // Arrange - no user in DbContext
        var nonExistentUserId = Guid.NewGuid();

        // Act
        var result = await _handler.HandleAsync(nonExistentUserId, "some-tenant");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsTenantInactive_WhenTargetTenantIsInactive()
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

        var inactiveTenant = new IdmtTenantInfo("tid", "inactive-tenant", "Inactive") { IsActive = false };
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("inactive-tenant"))
            .ReturnsAsync(inactiveTenant);

        // Act
        var result = await _handler.HandleAsync(userId, "inactive-tenant");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.Inactive", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsNoRolesAssigned_WhenUserHasNoRoles()
    {
        // Arrange
        var userId = Guid.NewGuid();
        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "noroles",
            Email = "noroles@test.com",
            TenantId = "sys-id"
        });
        await _dbContext.SaveChangesAsync();

        var activeTenant = new IdmtTenantInfo("tid", "active-tenant", "Active") { IsActive = true };
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("active-tenant"))
            .ReturnsAsync(activeTenant);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _handler.HandleAsync(userId, "active-tenant");

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NoRolesAssigned", result.FirstError.Code);
    }

    [Fact]
    public async Task ReactivatesExistingAccess_WhenRecordAlreadyExists()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "target-tid";

        _dbContext.Users.Add(new IdmtUser
        {
            Id = userId,
            UserName = "existinguser",
            Email = "existing@test.com",
            TenantId = "sys-id"
        });

        // Pre-existing inactive access record
        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = userId,
            TenantId = tenantId,
            IsActive = false,
            ExpiresAt = null
        });
        await _dbContext.SaveChangesAsync();

        var activeTenant = new IdmtTenantInfo(tenantId, "target-tenant", "Target") { IsActive = true };
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("target-tenant"))
            .ReturnsAsync(activeTenant);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(new List<string> { "SysAdmin" });

        var futureExpiry = new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero);

        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                "target-tenant",
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(Result.Success);

        // Act
        var result = await _handler.HandleAsync(userId, "target-tenant", futureExpiry);

        // Assert
        Assert.False(result.IsError);

        // Verify the access record was reactivated with new expiry
        var access = await _dbContext.TenantAccess
            .FirstOrDefaultAsync(ta => ta.UserId == userId && ta.TenantId == tenantId);

        Assert.NotNull(access);
        Assert.True(access.IsActive);
        Assert.Equal(futureExpiry, access.ExpiresAt);
    }

    [Fact]
    public async Task ReturnsAccessError_AndExecutesCompensatingAction_WhenSaveChangesFails()
    {
        // Arrange — build a completely separate handler whose DbContext throws on SaveChangesAsync.
        // We share an InMemory database name so the seed context and the throwing context see the same data.

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var sharedDbName = Guid.NewGuid().ToString();
        var dbOptions = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: sharedDbName)
            .Options;

        // Seed a user in a normal (non-throwing) context
        var userId = Guid.NewGuid();
        using (var seedContext = new IdmtDbContext(
            tenantAccessorMock.Object, dbOptions,
            currentUserServiceMock.Object, TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance))
        {
            seedContext.Users.Add(new IdmtUser
            {
                Id = userId,
                UserName = "compuser",
                Email = "comp@test.com",
                TenantId = "sys-id"
            });
            await seedContext.SaveChangesAsync();
        }

        // Create the throwing DbContext that shares the same InMemory database
        var throwingContext = new ThrowOnSaveDbContext(
            tenantAccessorMock.Object,
            new DbContextOptionsBuilder<ThrowOnSaveDbContext>()
                .UseInMemoryDatabase(databaseName: sharedDbName)
                .Options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        // Set up mocks
        var tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        var activeTenant = new IdmtTenantInfo("tid", "comp-tenant", "CompTenant") { IsActive = true };
        tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("comp-tenant"))
            .ReturnsAsync(activeTenant);

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(new List<string> { "SysAdmin" });

        var tenantOpsMock = new Mock<ITenantOperationService>();

        // Both calls to ExecuteInTenantScopeAsync return Success:
        //   1st call — tenant-scope user creation
        //   2nd call — compensating action after SaveChanges failure
        tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                "comp-tenant",
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(Result.Success);

        // Issue 19 fix: inject throwing context and mocks directly — no IServiceProvider wrapper.
        var handler = new GrantTenantAccess.GrantTenantAccessHandler(
            throwingContext,
            userManagerMock.Object,
            tenantStoreMock.Object,
            tenantOpsMock.Object,
            _timeProvider,
            NullLogger<GrantTenantAccess.GrantTenantAccessHandler>.Instance);

        // Act
        var result = await handler.HandleAsync(userId, "comp-tenant");

        // Assert — handler should return Tenant.AccessError after the compensating action
        Assert.True(result.IsError);
        Assert.Equal("Tenant.AccessError", result.FirstError.Code);

        // Verify the compensating action was invoked (2 total calls: tenant user creation + compensation)
        tenantOpsMock.Verify(
            x => x.ExecuteInTenantScopeAsync(
                "comp-tenant",
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()),
            Times.Exactly(2));
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    /// <summary>
    /// A test-only <see cref="IdmtDbContext"/> subclass whose <c>SaveChangesAsync</c> always
    /// throws a <see cref="DbUpdateException"/>, simulating a persistence failure so we can
    /// verify the handler's compensating action fires.
    /// </summary>
    private sealed class ThrowOnSaveDbContext : IdmtDbContext
    {
        public ThrowOnSaveDbContext(
            IMultiTenantContextAccessor multiTenantContextAccessor,
            DbContextOptions options,
            ICurrentUserService currentUserService,
            TimeProvider timeProvider,
            ILogger<IdmtDbContext> logger)
            : base(multiTenantContextAccessor, options, currentUserService, timeProvider, logger)
        {
        }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            throw new DbUpdateException("Simulated save failure");
        }
    }
}
