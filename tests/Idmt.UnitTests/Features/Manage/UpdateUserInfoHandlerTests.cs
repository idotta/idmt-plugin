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
    private readonly Mock<ICurrentUserService> _handlerCurrentUserServiceMock;
    private readonly Mock<ITokenRevocationService> _tokenRevocationServiceMock;
    private readonly IdmtDbContext _dbContext;
    private readonly UpdateUserInfo.UpdateUserInfoHandler _handler;

    public UpdateUserInfoHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _linkGeneratorMock = new Mock<IIdmtLinkGenerator>();
        _emailSenderMock = new Mock<IEmailSender<IdmtUser>>();
        _handlerCurrentUserServiceMock = new Mock<ICurrentUserService>();
        _tokenRevocationServiceMock = new Mock<ITokenRevocationService>();

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
            _handlerCurrentUserServiceMock.Object,
            _tokenRevocationServiceMock.Object,
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
    public async Task SkipsEmailFlow_WhenNoFieldsChanged()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "currentname");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        var request = new UpdateUserInfo.UpdateUserInfoRequest();

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.False(result.Value.EmailChangePending);
        _userManagerMock.Verify(x => x.GenerateChangeEmailTokenAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task DoesNotMutateEmail_WhenEmailChangeRequested_StagesPendingEmail()
    {
        // Arrange — invariant: user.Email column is NOT mutated; only PendingEmail is set.
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailChangeLink("old@test.com", "new@test.com", "change-token"))
            .Returns("https://example.com/confirm-email-change?token=change-token");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.True(result.Value.EmailChangePending);
        Assert.Equal("old@test.com", user.Email);
        Assert.Equal("new@test.com", user.PendingEmail);

        // ChangeEmailAsync MUST NOT be invoked at the staging step.
        _userManagerMock.Verify(
            x => x.ChangeEmailAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task SendsConfirmationLinkToNewEmail_WhenEmailChangeRequested()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailChangeLink("old@test.com", "new@test.com", "change-token"))
            .Returns("https://example.com/confirm-email-change?token=change-token");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _linkGeneratorMock.Verify(
            x => x.GenerateConfirmEmailChangeLink("old@test.com", "new@test.com", "change-token"),
            Times.Once);
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(
                user,
                "new@test.com",
                "https://example.com/confirm-email-change?token=change-token"),
            Times.Once);
    }

    [Fact]
    public async Task ReturnsResultEmailChangePendingTrue_WhenEmailChangeRequested()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _linkGeneratorMock
            .Setup(x => x.GenerateConfirmEmailChangeLink("old@test.com", "new@test.com", "change-token"))
            .Returns("https://example.com/confirm-email-change");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.True(result.Value.EmailChangePending);
    }

    [Fact]
    public async Task ReturnsResultEmailChangePendingFalse_WhenNoEmailChangeRequested()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "currentname");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.SetUserNameAsync(user, "newname"))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() => user.UserName = "newname");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "newname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.False(result.Value.EmailChangePending);
    }

    /// <summary>
    /// F25 (CD-1 regression): when both NewPassword and NewEmail are requested, the
    /// change-email token must validate at confirm time. The handler MUST flush + reload
    /// AFTER ChangePasswordAsync rotates SecurityStamp and BEFORE
    /// GenerateChangeEmailTokenAsync, so the token binds to the post-rotation stamp.
    /// </summary>
    [Fact]
    public async Task PasswordAndEmailChange_TokenStillValidAtConfirmTime()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);

        // Simulate ChangePasswordAsync rotating the SecurityStamp.
        var stampAtPasswordChange = string.Empty;
        _userManagerMock.Setup(x => x.ChangePasswordAsync(user, "OldP@ss1!", "NewP@ss1!"))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() =>
            {
                user.SecurityStamp = Guid.NewGuid().ToString();
                stampAtPasswordChange = user.SecurityStamp;
            });

        // Token generation must observe the rotated stamp.
        var stampAtTokenGen = string.Empty;
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync(() =>
            {
                stampAtTokenGen = user.SecurityStamp ?? string.Empty;
                return $"change-token-{user.SecurityStamp}";
            });

        _linkGeneratorMock.Setup(x => x.GenerateConfirmEmailChangeLink(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns("https://example.com/confirm-email-change");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(
            OldPassword: "OldP@ss1!",
            NewPassword: "NewP@ss1!",
            NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.True(result.Value.EmailChangePending);

        // Token must be generated AFTER password change rotates stamp.
        Assert.False(string.IsNullOrEmpty(stampAtPasswordChange));
        Assert.Equal(stampAtPasswordChange, stampAtTokenGen);

        // Now simulate the user clicking the link — confirm time. Identity's
        // ChangeEmailAsync validates the token against the user's CURRENT stamp.
        // Stamp has not rotated again, so the token validates.
        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", $"change-token-{stampAtPasswordChange}"))
            .ReturnsAsync(IdentityResult.Success);

        var confirmHandler = new Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeHandler(
            _userManagerMock.Object,
            _dbContext,
            NullLogger<Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeHandler>.Instance);

        var confirmRequest = new Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "new@test.com",
            Token: $"change-token-{stampAtPasswordChange}");

        var confirmResult = await confirmHandler.HandleAsync(confirmRequest);
        Assert.False(confirmResult.IsError);
    }

    /// <summary>
    /// F44 (CD-1 widened): same coupling for username + email change.
    /// </summary>
    [Fact]
    public async Task UsernameAndEmailChange_TokenStillValidAtConfirmTime()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "oldname", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);

        // Simulate SetUserNameAsync rotating the stamp.
        var stampAfterUsername = string.Empty;
        _userManagerMock.Setup(x => x.SetUserNameAsync(user, "newname"))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() =>
            {
                user.UserName = "newname";
                user.SecurityStamp = Guid.NewGuid().ToString();
                stampAfterUsername = user.SecurityStamp;
            });

        var stampAtTokenGen = string.Empty;
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync(() =>
            {
                stampAtTokenGen = user.SecurityStamp ?? string.Empty;
                return $"change-token-{user.SecurityStamp}";
            });

        _linkGeneratorMock.Setup(x => x.GenerateConfirmEmailChangeLink(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns("https://example.com/confirm-email-change");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(
            NewUsername: "newname",
            NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.True(result.Value.EmailChangePending);
        Assert.False(string.IsNullOrEmpty(stampAfterUsername));
        Assert.Equal(stampAfterUsername, stampAtTokenGen);

        _userManagerMock.Setup(x => x.ChangeEmailAsync(user, "new@test.com", $"change-token-{stampAfterUsername}"))
            .ReturnsAsync(IdentityResult.Success);

        var confirmHandler = new Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeHandler(
            _userManagerMock.Object,
            _dbContext,
            NullLogger<Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeHandler>.Instance);

        var confirmRequest = new Idmt.Plugin.Features.Auth.ConfirmEmailChange.ConfirmEmailChangeRequest(
            Email: "old@test.com",
            NewEmail: "new@test.com",
            Token: $"change-token-{stampAfterUsername}");

        var confirmResult = await confirmHandler.HandleAsync(confirmRequest);
        Assert.False(confirmResult.IsError);
    }

    /// <summary>
    /// Verifies the ordering invariant: GenerateChangeEmailTokenAsync runs strictly
    /// AFTER ChangePasswordAsync. Use a sequence to assert the exact call order.
    /// </summary>
    [Fact]
    public async Task FlushReloadOrderingPreserved_GenerateTokenAfterPasswordChange()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);

        var sequence = new MockSequence();
        _userManagerMock.InSequence(sequence)
            .Setup(x => x.ChangePasswordAsync(user, "OldP@ss1!", "NewP@ss1!"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.InSequence(sequence)
            .Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");

        _linkGeneratorMock.Setup(x => x.GenerateConfirmEmailChangeLink(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns("https://example.com/confirm-email-change");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(
            OldPassword: "OldP@ss1!",
            NewPassword: "NewP@ss1!",
            NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert: sequence will throw if ordering is violated.
        Assert.False(result.IsError);
        _userManagerMock.Verify(x => x.ChangePasswordAsync(user, "OldP@ss1!", "NewP@ss1!"), Times.Once);
        _userManagerMock.Verify(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"), Times.Once);
    }

    [Fact]
    public async Task DoesNotChangeEmail_WhenNewEmailSameAsCurrent()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("same@test.com");
        var user = await SeedUserAsync(email: "same@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("same@test.com")).ReturnsAsync(user);

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "same@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.False(result.Value.EmailChangePending);
        _userManagerMock.Verify(
            x => x.GenerateChangeEmailTokenAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()),
            Times.Never);
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task DoesNotChangeUsername_WhenNewUsernameSameAsCurrent()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "currentname");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "currentname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.False(result.Value.EmailChangePending);
        _userManagerMock.Verify(x => x.SetUserNameAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task ReturnsPasswordResetFailed_WhenChangePasswordFails()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "testuser");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.ChangePasswordAsync(user, "OldP@ss1!", "NewP@ss1!"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Bad", Description = "no" }));

        var request = new UpdateUserInfo.UpdateUserInfoRequest(
            OldPassword: "OldP@ss1!",
            NewPassword: "NewP@ss1!");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);

        // Email flow must NOT be triggered when password change failed.
        _emailSenderMock.Verify(
            x => x.SendConfirmationLinkAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_EmailOnlyChangeRequested_DoesNotRevokeTokens()
    {
        // Arrange — email-only change must NOT revoke bearer tokens at staging time.
        // Revocation happens naturally at confirm time via SecurityStamp rotation.
        var userId = Guid.NewGuid();
        var principal = CreatePrincipalWithEmail("old@test.com");
        var user = await SeedUserAsync(email: "old@test.com", username: "testuser", emailConfirmed: true);
        _userManagerMock.Setup(x => x.FindByEmailAsync("old@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GenerateChangeEmailTokenAsync(user, "new@test.com"))
            .ReturnsAsync("change-token");
        _linkGeneratorMock.Setup(x => x.GenerateConfirmEmailChangeLink(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns("https://example.com/confirm-email-change");

        _handlerCurrentUserServiceMock.SetupGet(x => x.UserId).Returns(userId);
        _handlerCurrentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewEmail: "new@test.com");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        Assert.True(result.Value.EmailChangePending);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_PasswordChangeRequested_RevokesTokens()
    {
        // Arrange — credentials path must still revoke (regression).
        var userId = Guid.NewGuid();
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "testuser");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.ChangePasswordAsync(user, "OldP@ss1!", "NewP@ss1!"))
            .ReturnsAsync(IdentityResult.Success);

        _handlerCurrentUserServiceMock.SetupGet(x => x.UserId).Returns(userId);
        _handlerCurrentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(
            OldPassword: "OldP@ss1!",
            NewPassword: "NewP@ss1!");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(userId, "tenant-1", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Handle_UsernameChangeRequested_RevokesTokens()
    {
        // Arrange — username change rotates SecurityStamp, must revoke bearer tokens.
        var userId = Guid.NewGuid();
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = await SeedUserAsync(email: "user@test.com", username: "oldname");
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.SetUserNameAsync(user, "newname"))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() => user.UserName = "newname");

        _handlerCurrentUserServiceMock.SetupGet(x => x.UserId).Returns(userId);
        _handlerCurrentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");

        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewUsername: "newname");

        // Act
        var result = await _handler.HandleAsync(request, principal);

        // Assert
        Assert.False(result.IsError);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(userId, "tenant-1", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Helper: persists a user to the in-memory IdmtDbContext so that EF tracks the entity.
    /// Required because the new staging path calls dbContext.Entry(user).ReloadAsync, which
    /// only works on tracked entities.
    /// </summary>
    private async Task<IdmtUser> SeedUserAsync(string email, string username, bool emailConfirmed = false)
    {
        var user = new IdmtUser
        {
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            UserName = username,
            NormalizedUserName = username.ToUpperInvariant(),
            EmailConfirmed = emailConfirmed,
            IsActive = true,
        };
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();
        return user;
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
