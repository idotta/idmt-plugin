using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class LoginHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<SignInManager<IdmtUser>> _signInManagerMock;
    private readonly Mock<IMultiTenantContextAccessor> _tenantAccessorMock;
    private readonly Mock<TimeProvider> _timeProviderMock;
    private readonly Login.LoginHandler _handler;

    public LoginHandlerTests()
    {
        var userStoreMock = Mock.Of<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock,
            null!, null!, null!, null!, null!, null!, null!, null!);

        // SignInManager requires UserManager, IHttpContextAccessor, IUserClaimsPrincipalFactory,
        // IOptions<IdentityOptions>, ILogger, IAuthenticationSchemeProvider, IUserConfirmation
        var httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock.Setup(x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);
        var serviceProviderMock = new Mock<IServiceProvider>();
        serviceProviderMock.Setup(x => x.GetService(typeof(IAuthenticationService)))
            .Returns(authServiceMock.Object);
        var httpContext = new DefaultHttpContext { RequestServices = serviceProviderMock.Object };
        // SignInManager.Context accesses HttpContextAccessor.HttpContext
        httpContextAccessorMock.Setup(x => x.HttpContext).Returns(httpContext);

        _signInManagerMock = new Mock<SignInManager<IdmtUser>>(
            _userManagerMock.Object,
            httpContextAccessorMock.Object,
            Mock.Of<IUserClaimsPrincipalFactory<IdmtUser>>(),
            Mock.Of<IOptions<IdentityOptions>>(),
            NullLogger<SignInManager<IdmtUser>>.Instance,
            Mock.Of<IAuthenticationSchemeProvider>(),
            Mock.Of<IUserConfirmation<IdmtUser>>());

        _tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _timeProviderMock = new Mock<TimeProvider>();
        _timeProviderMock.Setup(x => x.GetUtcNow()).Returns(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

        _handler = new Login.LoginHandler(
            _userManagerMock.Object,
            _signInManagerMock.Object,
            _tenantAccessorMock.Object,
            _timeProviderMock.Object,
            NullLogger<Login.LoginHandler>.Instance);
    }

    private static Login.LoginRequest CreateRequest(
        string? email = "test@example.com",
        string? username = null,
        string password = "Password123!",
        string? twoFactorCode = null,
        string? twoFactorRecoveryCode = null) =>
        new()
        {
            Email = email,
            Username = username,
            Password = password,
            TwoFactorCode = twoFactorCode,
            TwoFactorRecoveryCode = twoFactorRecoveryCode
        };

    private void SetupActiveTenant()
    {
        var tenant = new IdmtTenantInfo("tenant-id", "test-tenant", "Test Tenant");
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);
        _tenantAccessorMock.Setup(x => x.MultiTenantContext).Returns(context);
    }

    private static IdmtUser CreateActiveUser() =>
        new()
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            UserName = "testuser",
            TenantId = "tenant-id",
            IsActive = true
        };

    [Fact]
    public async Task ReturnsNotResolved_WhenTenantContextIsNull()
    {
        _tenantAccessorMock.Setup(x => x.MultiTenantContext).Returns((IMultiTenantContext)null!);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotResolved", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsInactive_WhenTenantIsInactive()
    {
        var tenant = new IdmtTenantInfo("tenant-id", "test-tenant", "Test Tenant") { IsActive = false };
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);
        _tenantAccessorMock.Setup(x => x.MultiTenantContext).Returns(context);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Tenant.Inactive", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenNeitherEmailNorUsernameProvided()
    {
        SetupActiveTenant();
        // Both email and username are null, so no user lookup occurs and user remains null
        var request = CreateRequest(email: null, username: null);

        var result = await _handler.HandleAsync(request);

        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenUserIsInactive()
    {
        SetupActiveTenant();
        var inactiveUser = CreateActiveUser();
        inactiveUser.IsActive = false;

        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com"))
            .ReturnsAsync(inactiveUser);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsLockedOut_WhenTwoFactorRequiredAndUserIsLockedOut()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.TwoFactorRequired);
        _userManagerMock.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Auth.LockedOut", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenTwoFactorCodeIsInvalid()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.TwoFactorRequired);
        _userManagerMock.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(user, It.IsAny<string>(), "invalid-code"))
            .ReturnsAsync(false);
        _userManagerMock.Setup(x => x.AccessFailedAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _handler.HandleAsync(CreateRequest(twoFactorCode: "invalid-code"));

        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
        _userManagerMock.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenRecoveryCodeIsInvalid()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.TwoFactorRequired);
        _userManagerMock.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.RedeemTwoFactorRecoveryCodeAsync(user, "bad-recovery"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidCode", Description = "Invalid" }));
        _userManagerMock.Setup(x => x.AccessFailedAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _handler.HandleAsync(CreateRequest(twoFactorRecoveryCode: "bad-recovery"));

        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
        _userManagerMock.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task ReturnsTwoFactorRequired_WhenBothCodesAreEmpty()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.TwoFactorRequired);
        _userManagerMock.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Auth.TwoFactorRequired", result.FirstError.Code);
    }

    [Fact]
    public async Task LogsWarning_WhenLastLoginAtUpdateFails()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.Success);
        _signInManagerMock.Setup(x => x.CreateUserPrincipalAsync(user))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        // Simulate UpdateAsync failure for LastLoginAt
        _userManagerMock.Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "UpdateFailed", Description = "Failed" }));

        var result = await _handler.HandleAsync(CreateRequest());

        // Should still succeed despite update failure (warning only)
        Assert.False(result.IsError);
        Assert.NotNull(result.Value.UserId);
        Assert.Equal(user.Id, result.Value.UserId);
    }

    [Fact]
    public async Task ReturnsUnexpected_WhenExceptionIsThrown()
    {
        SetupActiveTenant();
        _userManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Database connection lost"));

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("General.Unexpected", result.FirstError.Code);
    }
}
