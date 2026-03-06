using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ResendConfirmationEmailHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<IEmailSender<IdmtUser>> _emailSenderMock;
    private readonly Mock<IIdmtLinkGenerator> _linkGeneratorMock;
    private readonly ResendConfirmationEmail.ResendConfirmationEmailHandler _handler;

    public ResendConfirmationEmailHandlerTests()
    {
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _emailSenderMock = new Mock<IEmailSender<IdmtUser>>();
        _linkGeneratorMock = new Mock<IIdmtLinkGenerator>();

        _handler = new ResendConfirmationEmail.ResendConfirmationEmailHandler(
            _userManagerMock.Object,
            _linkGeneratorMock.Object,
            _emailSenderMock.Object,
            NullLogger<ResendConfirmationEmail.ResendConfirmationEmailHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsSuccess_WhenEmailAlreadyConfirmed()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "confirmed",
            Email = "confirmed@test.com",
            EmailConfirmed = true,
            IsActive = true,
            TenantId = "t1"
        };

        _userManagerMock
            .Setup(u => u.FindByEmailAsync("confirmed@test.com"))
            .ReturnsAsync(user);

        var request = new ResendConfirmationEmail.ResendConfirmationEmailRequest("confirmed@test.com");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert - returns success but no email should be sent
        Assert.False(result.IsError);
        _emailSenderMock.Verify(
            e => e.SendConfirmationLinkAsync(It.IsAny<IdmtUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
        _userManagerMock.Verify(
            u => u.GenerateEmailConfirmationTokenAsync(It.IsAny<IdmtUser>()),
            Times.Never);
    }
}
