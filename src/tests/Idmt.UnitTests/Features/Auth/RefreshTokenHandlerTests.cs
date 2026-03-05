using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Auth;

public class RefreshTokenHandlerTests
{
    private const string TenantClaimKey = "tenant";
    private const string TestTenantIdentifier = "test-tenant";

    private readonly Mock<IOptionsMonitor<BearerTokenOptions>> _bearerOptionsMock;
    private readonly Mock<TimeProvider> _timeProviderMock;
    private readonly Mock<SignInManager<IdmtUser>> _signInManagerMock;
    private readonly Mock<IMultiTenantContextAccessor<IdmtTenantInfo>> _tenantContextAccessorMock;
    private readonly IOptions<IdmtOptions> _idmtOptions;
    private readonly Mock<ITokenRevocationService> _tokenRevocationServiceMock;
    private readonly RefreshToken.RefreshTokenHandler _handler;

    public RefreshTokenHandlerTests()
    {
        _bearerOptionsMock = new Mock<IOptionsMonitor<BearerTokenOptions>>();
        _timeProviderMock = new Mock<TimeProvider>();

        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _signInManagerMock = CreateSignInManagerMock(userStoreMock);

        _tenantContextAccessorMock = new Mock<IMultiTenantContextAccessor<IdmtTenantInfo>>();

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

        _tokenRevocationServiceMock = new Mock<ITokenRevocationService>();

        _handler = new RefreshToken.RefreshTokenHandler(
            _bearerOptionsMock.Object,
            _timeProviderMock.Object,
            _signInManagerMock.Object,
            _tenantContextAccessorMock.Object,
            _idmtOptions,
            _tokenRevocationServiceMock.Object);
    }

    [Fact]
    public async Task ReturnsInvalidToken_WhenTicketIsNull()
    {
        // Arrange - protector returns null (unprotect fails)
        SetupBearerOptions(unprotectResult: null);

        var request = new RefreshToken.RefreshTokenRequest("invalid-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Token.Invalid", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsInvalidToken_WhenTokenIsExpired()
    {
        // Arrange - token expired in the past
        var expiredUtc = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiredUtc);
        SetupBearerOptions(unprotectResult: ticket);

        // TimeProvider returns a time after expiry
        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiredUtc.AddHours(1));

        var request = new RefreshToken.RefreshTokenRequest("expired-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Token.Invalid", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsInvalidToken_WhenSecurityStampValidationFails()
    {
        // Arrange - security stamp validation returns null
        var expiresUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc);
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((IdmtUser?)null);

        var request = new RefreshToken.RefreshTokenRequest("bad-stamp-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Token.Invalid", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenUserIsInactive()
    {
        // Arrange
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", IsActive = false, TenantId = "t1" };
        var expiresUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc);
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        var request = new RefreshToken.RefreshTokenRequest("inactive-user-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenTokenTenantClaimIsNull()
    {
        // Arrange - ticket has no tenant claim
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", IsActive = true, TenantId = "t1" };
        var expiresUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc, tenantClaim: null);
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        SetupTenantContext(TestTenantIdentifier);

        var request = new RefreshToken.RefreshTokenRequest("no-tenant-claim-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenTokenTenantDoesNotMatchCurrentTenant()
    {
        // Arrange - token tenant is different from current tenant
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", IsActive = true, TenantId = "t1" };
        var expiresUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc, tenantClaim: "other-tenant");
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        SetupTenantContext(TestTenantIdentifier);

        var request = new RefreshToken.RefreshTokenRequest("wrong-tenant-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUnauthorized_WhenCurrentTenantIsNull()
    {
        // Arrange - current tenant context is null
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", IsActive = true, TenantId = "t1" };
        var expiresUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc, tenantClaim: TestTenantIdentifier);
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        // No tenant context set - accessor returns null
        _tenantContextAccessorMock
            .SetupGet(a => a.MultiTenantContext)
            .Returns((IMultiTenantContext<IdmtTenantInfo>)null!);

        var request = new RefreshToken.RefreshTokenRequest("null-tenant-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsTokenRevoked_WhenTokenIsRevoked()
    {
        // Arrange - set up a valid refresh ticket that passes all existing checks
        var tenantId = "tid-12345";
        var user = new IdmtUser { UserName = "test", Email = "test@test.com", IsActive = true, TenantId = tenantId };
        var expiresUtc = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var issuedUtc = new DateTimeOffset(2026, 5, 2, 0, 0, 0, TimeSpan.Zero);
        var ticket = CreateTicket(expiresUtc: expiresUtc, tenantClaim: TestTenantIdentifier, issuedUtc: issuedUtc);
        SetupBearerOptions(unprotectResult: ticket);

        _timeProviderMock
            .Setup(t => t.GetUtcNow())
            .Returns(expiresUtc.AddHours(-1));

        _signInManagerMock
            .Setup(s => s.ValidateSecurityStampAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        SetupTenantContext(TestTenantIdentifier, tenantId);

        _tokenRevocationServiceMock
            .Setup(x => x.IsTokenRevokedAsync(user.Id, tenantId, issuedUtc.UtcDateTime, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var request = new RefreshToken.RefreshTokenRequest("revoked-token");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Token.Revoked", result.FirstError.Code);
    }

    #region Helpers

    private static Mock<SignInManager<IdmtUser>> CreateSignInManagerMock(Mock<IUserStore<IdmtUser>> userStoreMock)
    {
        var userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        return new Mock<SignInManager<IdmtUser>>(
            userManagerMock.Object,
            new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>().Object,
            new Mock<IUserClaimsPrincipalFactory<IdmtUser>>().Object,
            null!, null!, null!, null!);
    }

    private void SetupBearerOptions(AuthenticationTicket? unprotectResult)
    {
        var protectorMock = new Mock<ISecureDataFormat<AuthenticationTicket>>();
        protectorMock
            .Setup(p => p.Unprotect(It.IsAny<string>()))
            .Returns(unprotectResult!);

        var bearerOptions = new BearerTokenOptions
        {
            RefreshTokenProtector = protectorMock.Object
        };

        _bearerOptionsMock
            .Setup(o => o.Get(IdentityConstants.BearerScheme))
            .Returns(bearerOptions);
    }

    private static AuthenticationTicket CreateTicket(
        DateTimeOffset? expiresUtc,
        string? tenantClaim = TestTenantIdentifier,
        DateTimeOffset? issuedUtc = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "testuser"),
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
        };

        if (tenantClaim is not null)
        {
            claims.Add(new Claim(TenantClaimKey, tenantClaim));
        }

        var identity = new ClaimsIdentity(claims, "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var properties = new AuthenticationProperties
        {
            ExpiresUtc = expiresUtc,
            IssuedUtc = issuedUtc
        };

        return new AuthenticationTicket(principal, properties, IdentityConstants.BearerScheme);
    }

    private void SetupTenantContext(string? tenantIdentifier, string? tenantId = null)
    {
        if (tenantIdentifier is null)
        {
            _tenantContextAccessorMock
                .SetupGet(a => a.MultiTenantContext)
                .Returns((IMultiTenantContext<IdmtTenantInfo>)null!);
        }
        else
        {
            var tenantInfo = tenantId is not null
                ? new IdmtTenantInfo(tenantId, tenantIdentifier, tenantIdentifier)
                : new IdmtTenantInfo(tenantIdentifier, tenantIdentifier);
            var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
            _tenantContextAccessorMock
                .SetupGet(a => a.MultiTenantContext)
                .Returns(tenantContext);
        }
    }

    #endregion
}
