using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ForgotPasswordHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<IEmailSender<IdmtUser>> _emailSenderMock;
    private readonly Mock<IIdmtLinkGenerator> _linkGeneratorMock;
    private readonly ForgotPassword.ForgotPasswordHandler _handler;

    public ForgotPasswordHandlerTests()
    {
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _emailSenderMock = new Mock<IEmailSender<IdmtUser>>();
        _linkGeneratorMock = new Mock<IIdmtLinkGenerator>();

        _handler = new ForgotPassword.ForgotPasswordHandler(
            _userManagerMock.Object,
            _emailSenderMock.Object,
            _linkGeneratorMock.Object,
            NullLogger<ForgotPassword.ForgotPasswordHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsSuccess_WhenUserIsInactive()
    {
        // Arrange - user exists but is inactive
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            IsActive = false,
            TenantId = "t1"
        };

        _userManagerMock
            .Setup(u => u.FindByEmailAsync("inactive@test.com"))
            .ReturnsAsync(user);

        var request = new ForgotPassword.ForgotPasswordRequest("inactive@test.com");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert - returns success but no email should be sent
        Assert.False(result.IsError);
        _emailSenderMock.Verify(
            e => e.SendPasswordResetCodeAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
        _userManagerMock.Verify(
            u => u.GeneratePasswordResetTokenAsync(It.IsAny<IdmtUser>()),
            Times.Never);
    }

    [Fact]
    public async Task GeneratesPasswordResetLink_WhenUserExists()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            TenantId = "t1"
        };

        _userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(u => u.GeneratePasswordResetTokenAsync(user))
            .ReturnsAsync("reset-token-123");

        _linkGeneratorMock
            .Setup(l => l.GeneratePasswordResetLink("test@test.com", "reset-token-123"))
            .Returns("https://app.example.com/reset-password?token=encoded-token");

        var request = new ForgotPassword.ForgotPasswordRequest("test@test.com");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        _linkGeneratorMock.Verify(
            l => l.GeneratePasswordResetLink("test@test.com", "reset-token-123"),
            Times.Once);
        _emailSenderMock.Verify(
            e => e.SendPasswordResetCodeAsync(user, "test@test.com", "https://app.example.com/reset-password?token=encoded-token"),
            Times.Once);
    }
}
