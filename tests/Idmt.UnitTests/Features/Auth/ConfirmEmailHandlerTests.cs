using ErrorOr;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ConfirmEmailHandlerTests
{
    private static Mock<UserManager<IdmtUser>> CreateUserManagerMock()
    {
        return new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);
    }

    [Fact]
    public async Task ReturnsSuccess_WhenTokenValid()
    {
        // Arrange
        var user = new IdmtUser { UserName = "test", Email = "test@test.com" };
        var userManagerMock = CreateUserManagerMock();

        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);
        userManagerMock
            .Setup(u => u.ConfirmEmailAsync(user, "valid-token"))
            .ReturnsAsync(IdentityResult.Success);

        var handler = new ConfirmEmail.ConfirmEmailHandler(
            userManagerMock.Object,
            NullLogger<ConfirmEmail.ConfirmEmailHandler>.Instance);

        var request = new ConfirmEmail.ConfirmEmailRequest("test@test.com", "valid-token");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task ReturnsConfirmationFailed_WhenUserNotFound()
    {
        // Arrange
        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((IdmtUser?)null);

        var handler = new ConfirmEmail.ConfirmEmailHandler(
            userManagerMock.Object,
            NullLogger<ConfirmEmail.ConfirmEmailHandler>.Instance);

        var request = new ConfirmEmail.ConfirmEmailRequest("notfound@test.com", "token123");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsConfirmationFailed_WhenTokenIsInvalid()
    {
        // Arrange
        var user = new IdmtUser { UserName = "test", Email = "test@test.com" };
        var userManagerMock = CreateUserManagerMock();

        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync(user);
        userManagerMock
            .Setup(u => u.ConfirmEmailAsync(user, It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

        var handler = new ConfirmEmail.ConfirmEmailHandler(
            userManagerMock.Object,
            NullLogger<ConfirmEmail.ConfirmEmailHandler>.Instance);

        var request = new ConfirmEmail.ConfirmEmailRequest("test@test.com", "bad-token");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Email.ConfirmationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnexpected_OnException()
    {
        // Arrange
        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Database error"));

        var handler = new ConfirmEmail.ConfirmEmailHandler(
            userManagerMock.Object,
            NullLogger<ConfirmEmail.ConfirmEmailHandler>.Instance);

        var request = new ConfirmEmail.ConfirmEmailRequest("test@test.com", "token123");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("General.Unexpected", result.FirstError.Code);
    }

    [Fact]
    public void Handler_Constructor_DoesNotDependOnTenantOperationService()
    {
        // Regression: Step 5 removed body-supplied TenantIdentifier and the
        // ExecuteInTenantScopeAsync wrap. Handler now resolves UserManager
        // directly (canonical, global IdmtUser) without ITenantOperationService.
        var ctors = typeof(ConfirmEmail.ConfirmEmailHandler).GetConstructors();
        Assert.Single(ctors);
        var paramTypes = ctors[0].GetParameters().Select(p => p.ParameterType).ToArray();
        Assert.DoesNotContain(paramTypes, t => t.Name == "ITenantOperationService");
    }
}
