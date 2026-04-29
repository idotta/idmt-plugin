using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ConfirmEmailChangeHandlerTests : IDisposable
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly IdmtDbContext _dbContext;
    private readonly ConfirmEmailChange.ConfirmEmailChangeHandler _handler;

    public ConfirmEmailChangeHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var dummyTenant = new IdmtTenantInfo("system-test-tenant", "system-test", "System Test Tenant");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var currentUserServiceMock = new Mock<ICurrentUserService>();

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _handler = new ConfirmEmailChange.ConfirmEmailChangeHandler(
            _userManagerMock.Object,
            _dbContext,
            NullLogger<ConfirmEmailChange.ConfirmEmailChangeHandler>.Instance);
    }

    [Fact]
    public async Task Handle_ValidToken_CommitsEmail_AndClearsPendingEmail()
    {
        // Arrange
        var user = await SeedUserAsync("old@test.com", "user", pendingEmail: "new@test.com");
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "valid-token"))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() =>
            {
                // Identity's ChangeEmailAsync would mutate Email + EmailConfirmed atomically
                // AND persist via UserManager.UpdateAsync. Simulate the persistence so that
                // the handler's subsequent ReloadAsync sees the new state.
                user.Email = "new@test.com";
                user.NormalizedEmail = "NEW@TEST.COM";
                user.EmailConfirmed = true;
                _dbContext.SaveChangesAsync().GetAwaiter().GetResult();
            });

        var request = new ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "new@test.com",
            Token: "valid-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.Null(user.PendingEmail);
        Assert.Equal("new@test.com", user.Email);
        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task Handle_NoPendingEmail_ReturnsNoPendingChange()
    {
        // Arrange
        var user = await SeedUserAsync("old@test.com", "user", pendingEmail: null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);

        var request = new ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "new@test.com",
            Token: "any-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.NoPendingChange", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        _userManagerMock.Verify(
            x => x.ChangeEmailAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_PendingEmailMismatch_ReturnsPendingMismatch()
    {
        // Arrange — user has staged a different email than the request
        var user = await SeedUserAsync("old@test.com", "user", pendingEmail: "staged@test.com");
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);

        var request = new ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "different@test.com",
            Token: "any-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.PendingMismatch", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
        _userManagerMock.Verify(
            x => x.ChangeEmailAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_InvalidToken_ReturnsConfirmationFailed_AndPendingEmailIntact()
    {
        // Arrange
        var user = await SeedUserAsync("old@test.com", "user", pendingEmail: "new@test.com");
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "bad-token"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token." }));

        var request = new ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "new@test.com",
            Token: "bad-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
        // PendingEmail must remain set so the user can retry with a fresh staging.
        Assert.Equal("new@test.com", user.PendingEmail);
        Assert.Equal("old@test.com", user.Email);
    }

    [Fact]
    public async Task Handle_NonExistentUser_ReturnsConfirmationFailed()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByEmailAsync("missing@test.com"))
            .ReturnsAsync((IdmtUser?)null);

        var request = new ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "missing@test.com",
            NewEmail: "new@test.com",
            Token: "any-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
    }

    private async Task<IdmtUser> SeedUserAsync(string email, string username, string? pendingEmail)
    {
        var user = new IdmtUser
        {
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            UserName = username,
            NormalizedUserName = username.ToUpperInvariant(),
            EmailConfirmed = true,
            IsActive = true,
            PendingEmail = pendingEmail,
        };
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();
        return user;
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
