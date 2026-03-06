using System.Security.Claims;
using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Manage;

public class UpdateUserInfoHandlerTests : IDisposable
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<IIdmtLinkGenerator> _linkGeneratorMock;
    private readonly Mock<IEmailSender<IdmtUser>> _emailSenderMock;
    private readonly IdmtDbContext _dbContext;
    private readonly UpdateUserInfo.UpdateUserInfoHandler _handler;

    public UpdateUserInfoHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _linkGeneratorMock = new Mock<IIdmtLinkGenerator>();
        _emailSenderMock = new Mock<IEmailSender<IdmtUser>>();

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

        _handler = new UpdateUserInfo.UpdateUserInfoHandler(
            _userManagerMock.Object,
            _dbContext,
            _linkGeneratorMock.Object,
            _emailSenderMock.Object,
            NullLogger<UpdateUserInfo.UpdateUserInfoHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsClaimsNotFound_WhenEmailClaimMissing()
    {
        // Arrange - principal with no email claim
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Name, "testuser")
        ], "Bearer"));

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "newname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.ClaimsNotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsInactive_WhenUserIsInactive()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("inactive@test.com");
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            TenantId = "tenant-1",
            IsActive = false
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("inactive@test.com")).ReturnsAsync(user);

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "newname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.Inactive", result.FirstError.Code);
        Assert.Equal(ErrorType.Forbidden, result.FirstError.Type);
    }

    [Fact]
    public async Task SkipsUpdate_WhenNoFieldsChanged()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "currentname",
            Email = "user@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        // Request with no changes (all null)
        var request = new UpdateUserInfo.UpdateUserInfoRequest();

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<IdmtUser>()), Times.Never);
    }

    /// <summary>
    /// Verifies the critical fix: after a successful email change, a confirmation email is sent
    /// to the new address so the user has a recovery path and is not permanently locked out.
    /// </summary>
    [Fact]
    public async Task SendsConfirmationEmail_WhenEmailChanged()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "old@test.com",
            TenantId = "tenant-1",
            IsActive = true,
            EmailConfirmed = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "change-token"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync("confirm-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailLink("new@test.com", "confirm-token"))
            .Returns("https://example.com/confirm?token=confirm-token");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);

        // The link generator must be called with the NEW email address and the fresh confirm token
        _linkGeneratorMock.Verify(
            x => x.GenerateConfirmEmailLink("new@test.com", "confirm-token"),
            Times.Once);

        // The email sender must be called with the NEW email address and the generated link
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(
                user,
                "new@test.com",
                "https://example.com/confirm?token=confirm-token"),
            Times.Once);
    }

    /// <summary>
    /// Verifies the critical fix: when only the email changes, UpdateAsync must NOT be called.
    /// ChangeEmailAsync already persists the change; a second UpdateAsync would write with a
    /// stale concurrency stamp and could silently corrupt the user record.
    /// </summary>
    [Fact]
    public async Task DoesNotCallUpdateAsync_WhenOnlyEmailChanged()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "old@test.com",
            TenantId = "tenant-1",
            IsActive = true,
            EmailConfirmed = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "change-token"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync("confirm-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailLink("new@test.com", "confirm-token"))
            .Returns("https://example.com/confirm?token=confirm-token");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);

        // UpdateAsync must NOT be called — ChangeEmailAsync already saved the email change
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<IdmtUser>()), Times.Never);
    }

    /// <summary>
    /// Verifies that when both username and email change in the same request, UpdateAsync is
    /// still called exactly once for the username change (ChangeEmailAsync handles the email).
    /// </summary>
    [Fact]
    public async Task CallsUpdateAsync_WhenUsernameAndEmailBothChanged()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = new IdmtUser
        {
            UserName = "oldname",
            Email = "old@test.com",
            TenantId = "tenant-1",
            IsActive = true,
            EmailConfirmed = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.SetUserNameAsync(user, "newname"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "change-token"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync("confirm-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailLink("new@test.com", "confirm-token"))
            .Returns("https://example.com/confirm?token=confirm-token");
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "newname", NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);

        // UpdateAsync must be called exactly once for the username change
        _userManagerMock.Verify(x => x.UpdateAsync(user), Times.Once);

        // Confirmation email must still be sent for the email change
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(user, "new@test.com", It.IsAny<string>()),
            Times.Once);
    }

    [Fact]
    public async Task DoesNotChangeEmail_WhenNewEmailSameAsCurrent()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("same@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "same@test.com",
            TenantId = "tenant-1",
            IsActive = true,
            EmailConfirmed = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("same@test.com")).ReturnsAsync(user);

        // Request with same email as current
        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "same@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _userManagerMock.Verify(x => x.ChangeEmailAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<IdmtUser>()), Times.Never);
        _emailSenderMock.Verify(x => x.SendConfirmationLinkAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task DoesNotChangeUsername_WhenNewUsernameSameAsCurrent()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "currentname",
            Email = "user@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        // Request with same username as current
        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "currentname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _userManagerMock.Verify(x => x.SetUserNameAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<IdmtUser>()), Times.Never);
    }

    /// <summary>
    /// Verifies that a failed ChangeEmailAsync rolls back the transaction and returns an error
    /// without attempting to send a confirmation email.
    /// </summary>
    [Fact]
    public async Task ReturnsUpdateFailed_WhenChangeEmailFails()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "old@test.com",
            TenantId = "tenant-1",
            IsActive = true,
            EmailConfirmed = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", "change-token"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Error", Description = "Change failed" }));

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.UpdateFailed", result.FirstError.Code);

        // No confirmation email should be sent when the change itself failed
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    private static ClaimsPrincipal CreatePrincipalWithEmail(string email)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Name, "testuser")
        ], "Bearer"));
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
