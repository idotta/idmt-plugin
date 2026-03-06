using ErrorOr;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ConfirmEmailHandlerTests
{
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly ConfirmEmail.ConfirmEmailHandler _handler;

    public ConfirmEmailHandlerTests()
    {
        _tenantOpsMock = new Mock<ITenantOperationService>();

        _handler = new ConfirmEmail.ConfirmEmailHandler(
            _tenantOpsMock.Object,
            NullLogger<ConfirmEmail.ConfirmEmailHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsConfirmationFailed_WhenUserNotFound()
    {
        // Arrange
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((IdmtUser?)null);

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ConfirmEmail.ConfirmEmailRequest("test-tenant", "notfound@test.com", "token123");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsConfirmationFailed_WhenTokenIsInvalid()
    {
        // Arrange
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", TenantId = "t1" };

        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ConfirmEmailAsync(user, It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ConfirmEmail.ConfirmEmailRequest("test-tenant", "test@test.com", "bad-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnexpected_OnException()
    {
        // Arrange
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Database error"));

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ConfirmEmail.ConfirmEmailRequest("test-tenant", "test@test.com", "token123");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("General.Unexpected", result.FirstError.Code);
    }

    #region Helpers

    private void SetupTenantOpsToInvokeLambda(Mock<UserManager<IdmtUser>> userManagerMock)
    {
        _tenantOpsMock
            .Setup(t => t.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .Returns<string, Func<IServiceProvider, Task<ErrorOr<Success>>>, bool>(
                async (_, operation, _) =>
                {
                    var serviceProviderMock = new Mock<IServiceProvider>();
                    serviceProviderMock
                        .Setup(sp => sp.GetService(typeof(UserManager<IdmtUser>)))
                        .Returns(userManagerMock.Object);
                    return await operation(serviceProviderMock.Object);
                });
    }

    #endregion
}
