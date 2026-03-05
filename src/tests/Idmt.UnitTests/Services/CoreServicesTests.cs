using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Services;

/// <summary>
/// Unit tests for CurrentUserService.
/// Tests user context extraction, role checking, and user information retrieval.
/// Uses SetCurrentUser as designed with CurrentUserMiddleware.
/// </summary>
public class CurrentUserServiceTests
{
    private readonly Mock<IOptions<IdmtOptions>> _optionsMock;
    private readonly Mock<IMultiTenantContextAccessor> _tenantContextAccessorMock;
    private readonly CurrentUserService _service;

    public CurrentUserServiceTests()
    {
        _optionsMock = new Mock<IOptions<IdmtOptions>>();
        _optionsMock.Setup(x => x.Value).Returns(IdmtOptions.Default);
        _tenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _service = new CurrentUserService(_optionsMock.Object, _tenantContextAccessorMock.Object);
    }

    [Fact]
    public void UserId_ReturnsCurrentUserId_WhenUserExists()
    {
        var userId = Guid.NewGuid();
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, userId.ToString())
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.UserId;

        Assert.NotNull(result);
        Assert.Equal(userId, result);
    }

    [Fact]
    public void UserId_ReturnsNull_WhenUserDoesNotExist()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.UserId;

        Assert.Null(result);
    }

    [Fact]
    public void IsInRole_ReturnsTrue_WhenUserHasRole()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "Admin")
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.IsInRole("Admin");

        Assert.True(result);
    }

    [Fact]
    public void IsInRole_ReturnsFalse_WhenUserDoesNotHaveRole()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "User")
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.IsInRole("Admin");

        Assert.False(result);
    }

    [Fact]
    public void IsInRole_ReturnsFalse_WhenUserNotSet()
    {
        var result = _service.IsInRole("Admin");

        Assert.False(result);
    }

    [Fact]
    public void TenantIdentifier_ReturnsTenantIdentifier_WhenClaimExists()
    {
        const string tenantId = "tenant-123";
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(IdmtMultiTenantStrategy.DefaultClaim, tenantId)
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.TenantIdentifier;

        Assert.Equal(tenantId, result);
    }

    [Fact]
    public void TenantIdentifier_ReturnsNull_WhenClaimDoesNotExist()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.TenantIdentifier;

        Assert.Null(result);
    }

    [Fact]
    public void TenantIdentifier_ReturnsIdentifierFromTenantContext_WhenClaimDoesNotExist()
    {
        const string tenantIdentifier = "tenant-123";
        var tenantInfo = new IdmtTenantInfo("tenant-id-123", tenantIdentifier, "Test Tenant");
        var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);

        _tenantContextAccessorMock.Setup(x => x.MultiTenantContext).Returns(tenantContext);

        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.TenantIdentifier;

        Assert.Equal(tenantIdentifier, result);
    }

    [Fact]
    public void TenantIdentifier_ReturnsTenantIdentifier_WhenCustomClaimTypeIsConfigured()
    {
        const string customClaimType = "custom_tenant_claim";
        const string tenantId = "tenant-456";

        var customOptions = new IdmtOptions
        {
            MultiTenant = new MultiTenantOptions
            {
                StrategyOptions = new Dictionary<string, string>
                {
                    { IdmtMultiTenantStrategy.Claim, customClaimType }
                }
            }
        };

        var customOptionsMock = new Mock<IOptions<IdmtOptions>>();
        customOptionsMock.Setup(x => x.Value).Returns(customOptions);
        var customTenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var customService = new CurrentUserService(customOptionsMock.Object, customTenantContextAccessorMock.Object);

        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(customClaimType, tenantId)
            ]));

        customService.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = customService.TenantIdentifier;

        Assert.Equal(tenantId, result);
    }

    [Fact]
    public void IsActive_ReturnsTrue_WhenClaimIsTrue()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("is_active", "true")
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.IsActive;

        Assert.True(result);
    }

    [Fact]
    public void IsActive_ReturnsFalse_WhenClaimIsNotTrue()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("is_active", "false")
            ]));

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.IsActive;

        Assert.False(result);
    }

    [Fact]
    public void IsActive_ReturnsFalse_WhenClaimDoesNotExist()
    {
        var user = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());

        _service.SetCurrentUser(user, "127.0.0.1", "TestAgent/1.0");

        var result = _service.IsActive;

        Assert.False(result);
    }

    [Fact]
    public void IsActive_ReturnsFalse_WhenUserNotSet()
    {
        var result = _service.IsActive;

        Assert.False(result);
    }
}

/// <summary>
/// Extended unit tests for IdmtLinkGenerator covering additional scenarios.
/// </summary>
public class IdmtLinkGeneratorExtendedTests
{
    private readonly Mock<LinkGenerator> _linkGeneratorMock;
    private readonly Mock<IMultiTenantContextAccessor> _multiTenantContextAccessorMock;
    private readonly Mock<IMultiTenantContext> _multiTenantContextMock;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private readonly Mock<IOptions<IdmtOptions>> _optionsMock;
    private readonly Mock<ILogger<IdmtLinkGenerator>> _loggerMock;
    private readonly DefaultHttpContext _httpContext;
    private readonly IdmtOptions _options;
    private readonly IdmtTenantInfo _tenantInfo;
    private readonly IdmtLinkGenerator _service;

    public IdmtLinkGeneratorExtendedTests()
    {
        _linkGeneratorMock = new Mock<LinkGenerator>();
        _multiTenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _multiTenantContextMock = new Mock<IMultiTenantContext>();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _optionsMock = new Mock<IOptions<IdmtOptions>>();
        _loggerMock = new Mock<ILogger<IdmtLinkGenerator>>();
        _options = new IdmtOptions();
        _tenantInfo = new IdmtTenantInfo("tenant-1", "tenant-1", "Tenant 1");
        _httpContext = new DefaultHttpContext();
        _httpContext.Request.Scheme = "https";
        _httpContext.Request.Host = new HostString("demo.example");

        _optionsMock.Setup(x => x.Value).Returns(_options);
        _multiTenantContextMock.SetupGet(x => x.TenantInfo).Returns(_tenantInfo);
        _multiTenantContextAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(_multiTenantContextMock.Object);
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns(_httpContext);

        _service = new IdmtLinkGenerator(
            _linkGeneratorMock.Object,
            _multiTenantContextAccessorMock.Object,
            _httpContextAccessorMock.Object,
            _optionsMock.Object,
            _loggerMock.Object);
    }

    [Fact]
    public void GenerateConfirmEmailLink_ClientForm_IncludesAllQueryParameters()
    {
        const string email = "user@example.com";
        const string token = "confirm-token";
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ConfirmEmailFormPath = "/confirm-email";

        var result = _service.GenerateConfirmEmailLink(email, token);
        var uri = new Uri(result);
        var query = QueryHelpers.ParseQuery(uri.Query);

        Assert.Equal(_tenantInfo.Identifier, query["tenantIdentifier"].ToString());
        Assert.Equal(email, query["email"].ToString());
        // Token is Base64URL-encoded
        Assert.NotEmpty(query["token"].ToString());
    }

    [Fact]
    public void GeneratePasswordResetLink_IncludesAllQueryParameters()
    {
        const string email = "user@example.com";
        const string token = "reset-token";
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ResetPasswordFormPath = "/reset-password";

        var result = _service.GeneratePasswordResetLink(email, token);
        var uri = new Uri(result);
        var query = QueryHelpers.ParseQuery(uri.Query);

        Assert.Equal(_tenantInfo.Identifier, query["tenantIdentifier"].ToString());
        Assert.Equal(email, query["email"].ToString());
        // Token is Base64URL-encoded
        Assert.NotEmpty(query["token"].ToString());
    }

    [Fact]
    public void GenerateConfirmEmailLink_ClientForm_HandlesClientUrlWithTrailingSlash()
    {
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        _options.Application.ClientUrl = "https://client.example/";
        _options.Application.ConfirmEmailFormPath = "/confirm-email";

        var result = _service.GenerateConfirmEmailLink("user@example.com", "token");

        Assert.StartsWith("https://client.example/confirm-email", result);
    }

    [Fact]
    public void GenerateConfirmEmailLink_ClientForm_HandlePathWithoutLeadingSlash()
    {
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ConfirmEmailFormPath = "confirm-email";

        var result = _service.GenerateConfirmEmailLink("user@example.com", "token");

        Assert.Contains("/confirm-email", result);
    }
}
