using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class LogoutHandlerTests
{
    private const string TenantClaimKey = "tenant";

    private readonly Mock<ILogger<Logout.LogoutHandler>> _loggerMock;
    private readonly Mock<SignInManager<IdmtUser>> _signInManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Mock<IMultiTenantContextAccessor<IdmtTenantInfo>> _tenantContextAccessorMock;
    private readonly IOptions<IdmtOptions> _idmtOptions;
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

        _loggerMock = new Mock<ILogger<Logout.LogoutHandler>>();
        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _tenantContextAccessorMock = new Mock<IMultiTenantContextAccessor<IdmtTenantInfo>>();
        _tokenRevocationServiceMock = new Mock<ITokenRevocationService>();

        // Default: no tenant context resolved. Tests that need a resolved tenant override this.
        _tenantContextAccessorMock
            .SetupGet(x => x.MultiTenantContext)
            .Returns((IMultiTenantContext<IdmtTenantInfo>)null!);

        _idmtOptions = Options.Create(new IdmtOptions
        {
            MultiTenant = new MultiTenantOptions
            {
                StrategyOptions = new Dictionary<string, string>
                {
                    [IdmtMultiTenantStrategy.Claim] = TenantClaimKey
                }
            }
        });

        _handler = new Logout.LogoutHandler(
            _loggerMock.Object,
            _signInManagerMock.Object,
            _currentUserServiceMock.Object,
            _tenantContextAccessorMock.Object,
            _idmtOptions,
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
        var tenantId = "test-tenant-db-id";

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        SetupTenantContext(tenantDbId: tenantId, tenantIdentifier: "test-tenant");

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
    public async Task Logout_CallsRevokeUserTokensAsync_WhenUserAndTenantContextArePresent()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var tenantId = "test-tenant-db-id";

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        SetupTenantContext(tenantDbId: tenantId, tenantIdentifier: "test-tenant");

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _tokenRevocationServiceMock
            .Setup(x => x.RevokeUserTokensAsync(userId, tenantId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _handler.HandleAsync();

        // Assert: revocation is called with the tenant DB Id from the context accessor
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(userId, tenantId, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Logout_SkipsRevocation_WhenUserIdIsNull()
    {
        // Arrange
        _currentUserServiceMock.SetupGet(c => c.UserId).Returns((Guid?)null);
        SetupTenantContext(tenantDbId: "test-tenant-db-id", tenantIdentifier: "test-tenant");

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
    public async Task Logout_SkipsRevocationAndLogsWarning_WhenTenantContextIsNull()
    {
        // Arrange: the multi-tenant strategy produced no context (e.g. header or route strategy
        // does not fire during logout). The accessor default in the constructor returns null.
        // The principal has a tenant claim that the warning should surface in its message.
        var userId = Guid.NewGuid();
        var tenantIdentifierFromClaim = "acme-corp";
        var principal = BuildPrincipalWithTenantClaim(TenantClaimKey, tenantIdentifierFromClaim);

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        _currentUserServiceMock.SetupGet(c => c.User).Returns(principal);

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _handler.HandleAsync();

        // Assert: sign-out still returns 204 — the user is signed out even without revocation
        Assert.False(result.IsError);
        _tokenRevocationServiceMock.Verify(
            x => x.RevokeUserTokensAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);

        // Assert: warning is logged and identifies the tenant from bearer claims so operators
        // can diagnose the misconfigured strategy
        VerifyLogWarningContains(tenantIdentifierFromClaim);
    }

    [Fact]
    public async Task Logout_LogsWarning_WithNotPresentPlaceholder_WhenBothTenantContextAndClaimAreNull()
    {
        // Arrange: neither the multi-tenant context nor the bearer principal carry any tenant
        // information — the warning should still be emitted with a diagnostic placeholder.
        var userId = Guid.NewGuid();
        var principalWithNoTenantClaim = new ClaimsPrincipal(new ClaimsIdentity([], "Bearer"));

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        _currentUserServiceMock.SetupGet(c => c.User).Returns(principalWithNoTenantClaim);

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

        VerifyLogWarningContains("<not present in claims>");
    }

    [Fact]
    public async Task Logout_LogsWarning_WhenTenantContextExistsButTenantInfoIsNull()
    {
        // Arrange: Finbuckle returned a context object (resolution ran) but found no matching
        // tenant store entry — TenantInfo is null, so Id cannot be resolved.
        var userId = Guid.NewGuid();
        var tenantIdentifierFromClaim = "unknown-tenant";
        var principal = BuildPrincipalWithTenantClaim(TenantClaimKey, tenantIdentifierFromClaim);

        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(userId);
        _currentUserServiceMock.SetupGet(c => c.User).Returns(principal);

        var contextWithNullTenantInfo = new Mock<IMultiTenantContext<IdmtTenantInfo>>();
        contextWithNullTenantInfo.SetupGet(c => c.TenantInfo).Returns((IdmtTenantInfo)null!);
        _tenantContextAccessorMock
            .SetupGet(a => a.MultiTenantContext)
            .Returns(contextWithNullTenantInfo.Object);

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

        VerifyLogWarningContains(tenantIdentifierFromClaim);
    }

    [Fact]
    public async Task Logout_UsesConfiguredClaimKey_WhenReadingTenantIdentifierForWarning()
    {
        // Arrange: a non-default claim key is configured; the handler must read the tenant
        // identifier from the correct claim type when composing the warning message.
        const string customClaimKey = "custom_tenant_claim";
        const string tenantIdentifierValue = "my-org";

        var options = Options.Create(new IdmtOptions
        {
            MultiTenant = new MultiTenantOptions
            {
                StrategyOptions = new Dictionary<string, string>
                {
                    [IdmtMultiTenantStrategy.Claim] = customClaimKey
                }
            }
        });

        var principal = BuildPrincipalWithTenantClaim(customClaimKey, tenantIdentifierValue);
        _currentUserServiceMock.SetupGet(c => c.UserId).Returns(Guid.NewGuid());
        _currentUserServiceMock.SetupGet(c => c.User).Returns(principal);

        // Tenant context remains null (default)

        _signInManagerMock
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        var handlerWithCustomOptions = new Logout.LogoutHandler(
            _loggerMock.Object,
            _signInManagerMock.Object,
            _currentUserServiceMock.Object,
            _tenantContextAccessorMock.Object,
            options,
            _tokenRevocationServiceMock.Object);

        // Act
        await handlerWithCustomOptions.HandleAsync();

        // Assert: warning contains the value from the custom claim key
        VerifyLogWarningContains(tenantIdentifierValue);
    }

    #region Helpers

    /// <summary>
    /// Configures the tenant context accessor to return a fully resolved tenant.
    /// </summary>
    private void SetupTenantContext(string tenantDbId, string tenantIdentifier)
    {
        var tenantInfo = new IdmtTenantInfo(tenantDbId, tenantIdentifier, tenantIdentifier);
        var context = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
        _tenantContextAccessorMock
            .SetupGet(x => x.MultiTenantContext)
            .Returns(context);
    }

    private static ClaimsPrincipal BuildPrincipalWithTenantClaim(string claimKey, string claimValue)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(claimKey, claimValue)
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }

    /// <summary>
    /// Verifies that ILogger.LogWarning was called at least once with a formatted message
    /// that contains the expected substring.
    /// </summary>
    private void VerifyLogWarningContains(string expectedSubstring)
    {
        _loggerMock.Verify(
            l => l.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((state, _) => state.ToString()!.Contains(expectedSubstring)),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once,
            $"Expected a LogWarning call whose message contains '{expectedSubstring}'.");
    }

    #endregion
}
