using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class TokenLoginHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<SignInManager<IdmtUser>> _signInManagerMock;
    private readonly Mock<IMultiTenantContextAccessor> _tenantAccessorMock;
    private readonly Mock<IOptionsMonitor<BearerTokenOptions>> _bearerOptionsMock;
    private readonly Mock<TimeProvider> _timeProviderMock;
    private readonly Login.TokenLoginHandler _handler;

    public TokenLoginHandlerTests()
    {
        var userStoreMock = Mock.Of<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock,
            null!, null!, null!, null!, null!, null!, null!, null!);

        var httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        var httpContext = new DefaultHttpContext();
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
        _bearerOptionsMock = new Mock<IOptionsMonitor<BearerTokenOptions>>();
        _timeProviderMock = new Mock<TimeProvider>();
        _timeProviderMock.Setup(x => x.GetUtcNow()).Returns(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

        _handler = new Login.TokenLoginHandler(
            _userManagerMock.Object,
            _signInManagerMock.Object,
            _tenantAccessorMock.Object,
            _bearerOptionsMock.Object,
            _timeProviderMock.Object,
            NullLogger<Login.TokenLoginHandler>.Instance);
    }

    private static Login.LoginRequest CreateRequest(
        string? email = "test@example.com",
        string? username = null,
        string password = "Password123!") =>
        new()
        {
            Email = email,
            Username = username,
            Password = password
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

    private void SetupBearerTokenOptions()
    {
        var bearerOptions = new BearerTokenOptions
        {
            BearerTokenExpiration = TimeSpan.FromHours(1),
            RefreshTokenExpiration = TimeSpan.FromDays(14)
        };

        // Setup the ticket data format protectors
        var accessProtectorMock = new Mock<ISecureDataFormat<AuthenticationTicket>>();
        accessProtectorMock.Setup(x => x.Protect(It.IsAny<AuthenticationTicket>()))
            .Returns("test-access-token");

        var refreshProtectorMock = new Mock<ISecureDataFormat<AuthenticationTicket>>();
        refreshProtectorMock.Setup(x => x.Protect(It.IsAny<AuthenticationTicket>()))
            .Returns("test-refresh-token");

        bearerOptions.BearerTokenProtector = accessProtectorMock.Object;
        bearerOptions.RefreshTokenProtector = refreshProtectorMock.Object;

        _bearerOptionsMock.Setup(x => x.Get(IdentityConstants.BearerScheme)).Returns(bearerOptions);
    }

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
    public async Task ReturnsLockedOut_WhenPasswordCheckReturnsLockedOut()
    {
        SetupActiveTenant();
        var user = CreateActiveUser();
        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.LockedOut);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.True(result.IsError);
        Assert.Equal("Auth.LockedOut", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsTokenResponse_OnSuccessfulLogin()
    {
        SetupActiveTenant();
        SetupBearerTokenOptions();
        var user = CreateActiveUser();

        _userManagerMock.Setup(x => x.FindByEmailAsync("test@example.com")).ReturnsAsync(user);
        _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", true))
            .ReturnsAsync(SignInResult.Success);
        _signInManagerMock.Setup(x => x.CreateUserPrincipalAsync(user))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _handler.HandleAsync(CreateRequest());

        Assert.False(result.IsError);
        var response = result.Value;
        Assert.Equal("test-access-token", response.AccessToken);
        Assert.Equal("test-refresh-token", response.RefreshToken);
        Assert.Equal(3600L, response.ExpiresIn); // 1 hour in seconds
        Assert.Equal("Bearer", response.TokenType);
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
