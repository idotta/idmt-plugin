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
using Moq;

namespace Idmt.UnitTests.Features.Admin;

/// <summary>
/// Unit tests for the Phase 1 (canonical identity) <see cref="RevokeTenantAccess.RevokeTenantAccessHandler"/>.
/// Asserts the handler flips <c>TenantAccess.IsActive = false</c> in a single SaveChangesAsync, then
/// revokes outstanding bearer tokens by canonical UserId. No shadow IdmtUser deactivation, no
/// ExecuteInTenantScopeAsync hop.
/// </summary>
public class RevokeTenantAccessHandlerTests : IDisposable
{
    private readonly Mock<ITokenRevocationService> _tokenRevocationServiceMock;
    private readonly IdmtDbContext _dbContext;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Guid _callerUserId;
    private readonly RevokeTenantAccess.RevokeTenantAccessHandler _handler;

    public RevokeTenantAccessHandlerTests()
    {
        _tokenRevocationServiceMock = new Mock<ITokenRevocationService>();

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

        _handler = new RevokeTenantAccess.RevokeTenantAccessHandler(
            _dbContext,
            _userManagerMock.Object,
            _tenantStoreMock.Object,
            _tokenRevocationServiceMock.Object,
            _currentUserServiceMock.Object,
            NullLogger<RevokeTenantAccess.RevokeTenantAccessHandler>.Instance);
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

    private void StubTenant(string identifier, string id)
    {
        var t = new IdmtTenantInfo(id, identifier, identifier) { IsActive = true };
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
    public async Task Handle_NoExistingAccess_ReturnsAccessNotFound()
    {
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "u", Email = "u@test.com" };
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        StubFindUser(user);
        StubTenant("target-tenant", "tid-no-access");

        var result = await _handler.HandleAsync(user.Id, "target-tenant");

        Assert.True(result.IsError);
        Assert.Equal("Tenant.AccessNotFound", result.FirstError.Code);

        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_ActiveAccess_FlipsIsActiveFalse_AndRevokesTokens()
    {
        // Arrange
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "active", Email = "active@test.com" };
        _dbContext.Users.Add(user);
        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = user.Id,
            TenantId = "tid-active",
            IsActive = true
        });
        await _dbContext.SaveChangesAsync();

        StubFindUser(user);
        StubTenant("target-tenant", "tid-active");

        // Act
        var result = await _handler.HandleAsync(user.Id, "target-tenant");

        // Assert
        Assert.False(result.IsError);

        var ta = await _dbContext.TenantAccess
            .FirstOrDefaultAsync(x => x.UserId == user.Id && x.TenantId == "tid-active");
        Assert.NotNull(ta);
        Assert.False(ta!.IsActive);

        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(user.Id, "tid-active", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Handle_RevokeUserTokensCalledWithCanonicalUserId()
    {
        // Regression for N1: token revocation must key on canonical user.Id, never a shadow id.
        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "canonical", Email = "canonical@test.com" };
        _dbContext.Users.Add(user);
        _dbContext.TenantAccess.Add(new TenantAccess
        {
            UserId = user.Id,
            TenantId = "tid-canonical",
            IsActive = true
        });
        await _dbContext.SaveChangesAsync();

        StubFindUser(user);
        StubTenant("target-tenant", "tid-canonical");

        Guid? capturedUserId = null;
        string? capturedTenantId = null;
        _tokenRevocationServiceMock
            .Setup(x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, string, CancellationToken>((uid, tid, _) =>
            {
                capturedUserId = uid;
                capturedTenantId = tid;
            })
            .Returns(Task.CompletedTask);

        var result = await _handler.HandleAsync(user.Id, "target-tenant");

        Assert.False(result.IsError);
        Assert.Equal(user.Id, capturedUserId);
        Assert.Equal("tid-canonical", capturedTenantId);
    }

    [Fact]
    public async Task Handle_AtomicityWhenSaveChangesThrows_NoStateChange_NoTokenRevocation()
    {
        // Arrange — share an InMemory DB name so the throwing context observes seed data.
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

        var user = new IdmtUser { Id = Guid.NewGuid(), UserName = "atomic-rev", Email = "atomic-rev@test.com" };
        using (var seedContext = new IdmtDbContext(
            tenantAccessorMock.Object, dbOptions,
            currentUserServiceMock.Object, TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance))
        {
            seedContext.Users.Add(user);
            seedContext.TenantAccess.Add(new TenantAccess
            {
                UserId = user.Id,
                TenantId = "tid-atomic-rev",
                IsActive = true
            });
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
            .Setup(x => x.GetByIdentifierAsync("atomic-rev-tenant"))
            .ReturnsAsync(new IdmtTenantInfo("tid-atomic-rev", "atomic-rev-tenant", "Atomic Rev") { IsActive = true });

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id.ToString()))
            .ReturnsAsync(user);

        var tokenRevMock = new Mock<ITokenRevocationService>();

        var handler = new RevokeTenantAccess.RevokeTenantAccessHandler(
            throwingContext,
            userManagerMock.Object,
            tenantStoreMock.Object,
            tokenRevMock.Object,
            currentUserServiceMock.Object,
            NullLogger<RevokeTenantAccess.RevokeTenantAccessHandler>.Instance);

        // Act
        var result = await handler.HandleAsync(user.Id, "atomic-rev-tenant");

        // Assert — handler returns Tenant.AccessError; no IsActive flip persists; no token revocation called.
        Assert.True(result.IsError);
        Assert.Equal("Tenant.AccessError", result.FirstError.Code);

        using (var verifyContext = new IdmtDbContext(
            tenantAccessorMock.Object, dbOptions,
            currentUserServiceMock.Object, TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance))
        {
            var ta = await verifyContext.TenantAccess
                .FirstOrDefaultAsync(x => x.UserId == user.Id && x.TenantId == "tid-atomic-rev");
            Assert.NotNull(ta);
            Assert.True(ta!.IsActive);
        }

        tokenRevMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    /// <summary>
    /// A test-only <see cref="IdmtDbContext"/> subclass whose <c>SaveChangesAsync</c> always
    /// throws a <see cref="DbUpdateException"/>, simulating a persistence failure so we can
    /// assert atomicity (no state change, error returned, no downstream side-effects).
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
