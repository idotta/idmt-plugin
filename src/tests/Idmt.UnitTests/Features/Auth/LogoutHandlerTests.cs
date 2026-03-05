using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class LogoutHandlerTests
{
    private readonly Mock<SignInManager<IdmtUser>> _signInManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Mock<ITokenRevocationService> _tokenRevocationServiceMock;
    private readonly Logout.LogoutHandler _handler;

    public LogoutHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _signInManagerMock = new Mock<SignInManager<IdmtUser>>(
            userManagerMock.Object,
            new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>().Object,
            new Mock<IUserClaimsPrincipalFactory<IdmtUser>>().Object,
            null!, null!, null!, null!);

        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _tokenRevocationServiceMock = new Mock<ITokenRevocationService>();

        _handler = new Logout.LogoutHandler(
            NullLogger<Logout.LogoutHandler>.Instance,
            _signInManagerMock.Object,
            _currentUserServiceMock.Object,
            _tokenRevocationServiceMock.Object);
    }

    [Fact]
    public async Task ReturnsUnexpected_WhenSignOutThrows()
    {
        // Arrange
        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .ThrowsAsync(new InvalidOperationException("SignOut failed"));

        // Act
        var result = await _handler.HandleAsync();

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("General.Unexpected", result.FirstError.Code);
    }

    [Fact]
    public async Task Logout_ReturnsSuccess_OnHappyPath()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "test-tenant-id";

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        _currentUserServiceMock.SetupGet(c => c.TenantId).Returns(tenantId);

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _tokenRevocationServiceMock
            .Setup(x => x.RevokeUserTokensAsync(userId, tenantId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.HandleAsync();

        // Assert
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task Logout_CallsRevokeUserTokensAsync_WhenUserAndTenantIdArePresent()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "test-tenant-id";

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        _currentUserServiceMock.SetupGet(c => c.TenantId).Returns(tenantId);

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _tokenRevocationServiceMock
            .Setup(x => x.RevokeUserTokensAsync(userId, tenantId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _handler.HandleAsync();

        // Assert
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(userId, tenantId, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Logout_SkipsRevocation_WhenUserIdIsNull()
    {
        // Arrange
        _currentUserServiceMock.SetupGet(c => c.UserId).Returns((Guid?)null);
        _currentUserServiceMock.SetupGet(c => c.TenantId).Returns("test-tenant-id");

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.HandleAsync();

        // Assert
        Assert.False(result.IsError);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Logout_SkipsRevocation_WhenTenantIdIsNull()
    {
        // Arrange
        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(Guid.NewGuid());
        _currentUserServiceMock.SetupGet(c => c.TenantId).Returns((string?)null);

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.HandleAsync();

        // Assert
        Assert.False(result.IsError);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
