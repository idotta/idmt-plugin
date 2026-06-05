using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class ResetPasswordHandlerTests
{
    private static Mock<UserManager<IdmtUser>> CreateUserManagerMock()
    {
        return new Mock<UserManager<IdmtUser>>(
            new Mock<IUserStore<IdmtUser>>().Object,
            null!, null!, null!, null!, null!, null!, null!, null!);
    }

    private static ResetPassword.ResetPasswordHandler CreateHandler(Mock<UserManager<IdmtUser>> userManagerMock)
    {
        return new ResetPassword.ResetPasswordHandler(
            userManagerMock.Object,
            NullLogger<ResetPassword.ResetPasswordHandler>.Instance);
    }

    [Fact]
    public async Task Handle_InactiveUser_ReturnsResetFailed()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            IsActive = false,
        };

        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync("inactive@test.com"))
            .ReturnsAsync(user);

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("inactive@test.com", "token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_NonExistentEmail_ReturnsResetFailed()
    {
        // Arrange
        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((IdmtUser?)null);

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("nobody@test.com", "token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_InvalidToken_ReturnsResetFailed()
    {
        // Arrange
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
        };

        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "bad-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("test@test.com", "bad-token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Password.ResetFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task Handle_ValidToken_ResetsPassword_NoEmailConfirmedFlip()
    {
        // C7 regression: password reset MUST NOT mutate EmailConfirmed.
        // Arrange — pre-seed user with EmailConfirmed = false.
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            EmailConfirmed = false,
        };

        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "valid-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Success);

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("test@test.com", "valid-token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.False(user.EmailConfirmed);
    }

    [Fact]
    public async Task Handle_ValidToken_ResetsPassword_PreservesEmailConfirmedTrue()
    {
        // Regression: handler should not flip EmailConfirmed in either direction.
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            EmailConfirmed = true,
        };

        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "valid-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Success);

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("test@test.com", "valid-token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task Handle_NoLongerInvokesUpdateAsyncForEmailConfirmedFlip()
    {
        // C7 regression: handler must not call UpdateAsync to flip EmailConfirmed.
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "test@test.com",
            IsActive = true,
            EmailConfirmed = false,
        };

        var userManagerMock = CreateUserManagerMock();
        userManagerMock
            .Setup(u => u.FindByEmailAsync("test@test.com"))
            .ReturnsAsync(user);

        userManagerMock
            .Setup(u => u.ResetPasswordAsync(user, "valid-token", "NewPass123!"))
            .ReturnsAsync(IdentityResult.Success);

        var handler = CreateHandler(userManagerMock);
        var request = new ResetPassword.ResetPasswordRequest("test@test.com", "valid-token", "NewPass123!");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        userManagerMock.Verify(u => u.UpdateAsync(It.IsAny<IdmtUser>()), Times.Never);
    }

    [Fact]
    public void Handler_Constructor_DoesNotDependOnTenantOperationService()
    {
        // Regression: ctor signature should accept UserManager + ILogger only.
        var ctors = typeof(ResetPassword.ResetPasswordHandler).GetConstructors();
        Assert.Single(ctors);
        var paramTypes = ctors[0].GetParameters().Select(p => p.ParameterType).ToArray();
        Assert.Contains(paramTypes, t => t == typeof(UserManager<IdmtUser>));
        Assert.DoesNotContain(paramTypes, t => t.Name == "ITenantOperationService");
    }
}
