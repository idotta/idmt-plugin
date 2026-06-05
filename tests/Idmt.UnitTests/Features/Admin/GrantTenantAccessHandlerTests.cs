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

/// <summary>
/// Unit tests for the Phase 1 (canonical identity) <see cref="GrantTenantAccess.GrantTenantAccessHandler"/>.
/// Asserts the handler writes ONLY a TenantAccess row in a single SaveChangesAsync — no shadow IdmtUser
/// creation, no ExecuteInTenantScopeAsync hop, no compensation.
/// </summary>
public class GrantTenantAccessHandlerTests : IDisposable
{
    private readonly FakeTimeProvider _timeProvider;
    private readonly IdmtDbContext _dbContext;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Guid _callerUserId;
    private readonly GrantTenantAccess.GrantTenantAccessHandler _handler;

    public GrantTenantAccessHandlerTests()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 3, 4, 12, 0, 0, TimeSpan.Zero));

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _callerUserId = Guid.NewGuid();
        _currentUserServiceMock.SetupGet(x => x.UserId).Returns(_callerUserId);
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var dbOptions = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            dbOptions,
            _currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _handler = new GrantTenantAccess.GrantTenantAccessHandler(
            _dbContext,
            _userManagerMock.Object,
            _tenantStoreMock.Object,
            _currentUserServiceMock.Object,
            _timeProvider,
            NullLogger<GrantTenantAccess.GrantTenantAccessHandler>.Instance);
    }

    private void StubFindUser(IdmtUser user)
    {
        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id.ToString()))
            .ReturnsAsync(user);
    }

    private void StubFindUser_NotFound(Guid userId)
    {
        _userManagerMock
            .Setup(x => x.FindByIdAsync(userId.ToString()))
            .ReturnsAsync((IdmtUser?)null);
    }

    private void StubTenant(string identifier, string id, bool isActive)
    {
        var t = new IdmtTenantInfo(id, identifier, identifier) { IsActive = isActive };
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync(identifier))
            .ReturnsAsync(t);
    }

    private void StubTenant_NotFound(string identifier)
    {
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync(identifier))
            .ReturnsAsync((IdmtTenantInfo?)null);
    }

    [Fact]
    public async Task ReturnsValidationError_WhenExpiresAtIsInPast()
    {
        var pastDate = new DateTimeOffset(2026, 3, 3, 0, 0, 0, TimeSpan.Zero);

        var result = await _handler.HandleAsync(Guid.NewGuid(), "some-tenant", pastDate);

        Assert.True(result.IsError);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        Assert.Equal("ExpiresAt", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsValidationError_WhenExpiresAtEqualsNow()
    {
        var exactNow = _timeProvider.GetUtcNow();

        var result = await _handler.HandleAsync(Guid.NewGuid(), "some-tenant", exactNow);

        Assert.True(result.IsError);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        Assert.Equal("ExpiresAt", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_NullCurrentUser_ReturnsUnauthorized()
    {
        _currentUserServiceMock.SetupGet(x => x.UserId).Returns((Guid?)null);

        var result = await _handler.HandleAsync(Guid.NewGuid(), "some-tenant");

        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_SelfTarget_ReturnsForbidden()
    {
        var result = await _handler.HandleAsync(_callerUserId, "some-tenant");

        Assert.True(result.IsError);
        Assert.Equal("General.SelfTarget", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_NonExistentUser_ReturnsUserNotFound()
    {
        var nonExistentUserId = Guid.NewGuid();
        StubFindUser_NotFound(nonExistentUserId);

        var result = await _handler.HandleAsync(nonExistentUserId, "some-tenant");

        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_NonExistentTenant_ReturnsTenantNotFound()
    {
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "u", Email = "u@test.com" };
        StubFindUser(user);
        StubTenant_NotFound("nope-tenant");

        var result = await _handler.HandleAsync(user.Id, "nope-tenant");

        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_InactiveTenant_ReturnsTenantInactive()
    {
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "u", Email = "u@test.com" };
        StubFindUser(user);
        StubTenant("inactive-tenant", "tid-inactive", isActive: false);

        var result = await _handler.HandleAsync(user.Id, "inactive-tenant");

        Assert.True(result.IsError);
        Assert.Equal("Tenant.Inactive", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_NewGrant_InsertsTenantAccessRow_NoUserCreation()
    {
        // Arrange
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "newgrant", Email = "newgrant@test.com" };
        // Persist canonically so dbContext.Users count baseline is 1 — handler must not increment it.
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        StubFindUser(user);
        StubTenant("target-tenant", "tid-new", isActive: true);

        var beforeUsers = await _dbContext.Users.CountAsync();
        var beforeTenantAccess = await _dbContext.TenantAccess.CountAsync();

        // Act
        var result = await _handler.HandleAsync(user.Id, "target-tenant");

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(beforeUsers, await _dbContext.Users.CountAsync());
        Assert.Equal(beforeTenantAccess + 1, await _dbContext.TenantAccess.CountAsync());

        var ta = await _dbContext.TenantAccess
            .FirstOrDefaultAsync(x => x.UserId == user.Id && x.TenantId == "tid-new");
        Assert.NotNull(ta);
        Assert.True(ta!.IsActive);
        Assert.Null(ta.ExpiresAt);

        // Belt-and-braces: no shadow user creation should ever invoke UserManager.CreateAsync.
        _userManagerMock.Verify(
            x => x.CreateAsync(It.IsAny<IdmtUser>()),
            Times.Never);
        _userManagerMock.Verify(
            x => x.CreateAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_ExistingGrant_UpdatesIsActiveAndExpiresAt()
    {
        // Arrange
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "existing", Email = "existing@test.com" };
        _dbContext.Users.Add(user);
        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = user.Id,
            TenantId = "tid-existing",
            IsActive = false,
            ExpiresAt = null
        });
        await _dbContext.SaveChangesAsync();

        StubFindUser(user);
        StubTenant("target-tenant", "tid-existing", isActive: true);

        var futureExpiry = new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero);

        // Act
        var result = await _handler.HandleAsync(user.Id, "target-tenant", futureExpiry);

        // Assert
        Assert.False(result.IsError);

        var ta = await _dbContext.TenantAccess
            .FirstOrDefaultAsync(x => x.UserId == user.Id && x.TenantId == "tid-existing");
        Assert.NotNull(ta);
        Assert.True(ta!.IsActive);
        Assert.Equal(futureExpiry, ta.ExpiresAt);

        // Single row only — no duplicate insert.
        var rowCount = await _dbContext.TenantAccess
            .CountAsync(x => x.UserId == user.Id && x.TenantId == "tid-existing");
        Assert.Equal(1, rowCount);
    }

    [Fact]
    public async Task Handle_AtomicityWhenSaveChangesThrows_NoPartialState()
    {
        // Arrange — share an InMemory DB name so the throwing context sees the same data the seed context wrote.
        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();
        currentUserServiceMock.SetupGet(x => x.UserId).Returns(Guid.NewGuid());
        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var sharedDbName = Guid.NewGuid().ToString();
        var dbOptions = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: sharedDbName)
            .Options;

        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "atomic", Email = "atomic@test.com" };
        using (var seedContext = new IdmtDbContext(
            tenantAccessorMock.Object, dbOptions,
            currentUserServiceMock.Object, TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance))
        {
            seedContext.Users.Add(user);
            await seedContext.SaveChangesAsync();
        }

        var throwingContext = new ThrowOnSaveDbContext(
            tenantAccessorMock.Object,
            new DbContextOptionsBuilder<ThrowOnSaveDbContext>()
                .UseInMemoryDatabase(databaseName: sharedDbName)
                .Options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        var tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("atomic-tenant"))
            .ReturnsAsync(new IdmtTenantInfo("tid-atomic", "atomic-tenant", "Atomic") { IsActive = true });

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id.ToString()))
            .ReturnsAsync(user);

        var handler = new GrantTenantAccess.GrantTenantAccessHandler(
            throwingContext,
            userManagerMock.Object,
            tenantStoreMock.Object,
            currentUserServiceMock.Object,
            _timeProvider,
            NullLogger<GrantTenantAccess.GrantTenantAccessHandler>.Instance);

        // Act
        var result = await handler.HandleAsync(user.Id, "atomic-tenant");

        // Assert — handler returns Tenant.AccessError; no TenantAccess row persists.
        Assert.True(result.IsError);
        Assert.Equal("Tenant.AccessError", result.FirstError.Code);

        using (var verifyContext = new IdmtDbContext(
            tenantAccessorMock.Object, dbOptions,
            currentUserServiceMock.Object, TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance))
        {
            var anyTenantAccess = await verifyContext.TenantAccess
                .AnyAsync(x => x.UserId == user.Id && x.TenantId == "tid-atomic");
            Assert.False(anyTenantAccess);
        }
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    /// <summary>
    /// A test-only <see cref="IdmtDbContext"/> subclass whose <c>SaveChangesAsync</c> always
    /// throws a <see cref="DbUpdateException"/>, simulating a persistence failure so we can
    /// assert atomicity (no partial state, error returned).
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
