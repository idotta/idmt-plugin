using ErrorOr;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ResetPasswordHandlerTests
{
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly ResetPassword.ResetPasswordHandler _handler;

    public ResetPasswordHandlerTests()
    {
        _tenantOpsMock = new Mock<ITenantOperationService>();

        _handler = new ResetPassword.ResetPasswordHandler(
            _tenantOpsMock.Object,
            NullLogger<ResetPassword.ResetPasswordHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsResetFailed_WhenUserIsInactive()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            IsActive = false,
            TenantId = "t1"
        };

        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync("inactive@test.com"))
            .ReturnsAsync(user);

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ResetPassword.ResetPasswordRequest("test-tenant", "inactive@test.com", "token", "NewPass123!");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsResetFailed_WhenIdentityResetFails()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            TenantId = "t1"
        };

        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "bad-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ResetPassword.ResetPasswordRequest("test-tenant", "test@test.com", "bad-token", "NewPass123!");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task SetsEmailConfirmed_WhenUserEmailWasUnconfirmed()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            EmailConfirmed = false,
            TenantId = "t1"
        };

        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object, null!, null!, null!, null!, null!, null!, null!, null!);

        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "valid-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Success);

        userManagerMock
            .Setup(u => u.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        SetupTenantOpsToInvokeLambda(userManagerMock);

        var request = new ResetPassword.ResetPasswordRequest("test-tenant", "test@test.com", "valid-token", "NewPass123!");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.True(user.EmailConfirmed);
        userManagerMock.Verify(u => u.UpdateAsync(user), Times.Once);
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
