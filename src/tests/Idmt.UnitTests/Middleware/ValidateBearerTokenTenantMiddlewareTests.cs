using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Middleware;

public class ValidateBearerTokenTenantMiddlewareTests
{
    private readonly Mock<IMultiTenantContextAccessor> _tenantAccessorMock;
    private readonly Mock<IOptions<IdmtOptions>> _optionsMock;
    private readonly Mock<ILogger<ValidateBearerTokenTenantMiddleware>> _loggerMock;
    private readonly ValidateBearerTokenTenantMiddleware _middleware;
    private readonly IdmtOptions _options;

    public ValidateBearerTokenTenantMiddlewareTests()
    {
        _tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _optionsMock = new Mock<IOptions<IdmtOptions>>();
        _loggerMock = new Mock<ILogger<ValidateBearerTokenTenantMiddleware>>();
        _options = new IdmtOptions();
        _optionsMock.Setup(x => x.Value).Returns(_options);

        _middleware = new ValidateBearerTokenTenantMiddleware(
            _tenantAccessorMock.Object,
            _optionsMock.Object,
            _loggerMock.Object);
    }

    [Fact]
    public async Task InvokeAsync_UnauthenticatedRequest_PassesThrough()
    {
        var context = new DefaultHttpContext();
        var nextCalled = false;

        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_CookieAuthRequest_PassesThrough()
    {
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "user") }, "Cookie");
        context.User = new ClaimsPrincipal(identity);
        // No Bearer header
        var nextCalled = false;

        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_MissingTenantClaim_Returns401()
    {
        var context = CreateBearerContext(tenantClaimValue: null);
        SetupTenantContext("test-tenant");

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_MismatchedTenantClaim_Returns403()
    {
        var context = CreateBearerContext(tenantClaimValue: "tenant-a");
        SetupTenantContext("tenant-b");

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_MatchingTenantClaim_PassesThrough()
    {
        var context = CreateBearerContext(tenantClaimValue: "test-tenant");
        SetupTenantContext("test-tenant");

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_ExceptionInValidation_Returns401()
    {
        var context = CreateBearerContext(tenantClaimValue: "test-tenant");
        // Setup accessor to throw
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext)
            .Throws(new InvalidOperationException("test exception"));

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    private DefaultHttpContext CreateBearerContext(string? tenantClaimValue)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer test-token";

        var claims = new List<Claim> { new(ClaimTypes.Name, "user") };
        if (tenantClaimValue != null)
        {
            var claimKey = _options.MultiTenant.StrategyOptions.GetValueOrDefault(
                IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);
            claims.Add(new Claim(claimKey, tenantClaimValue));
        }

        var identity = new ClaimsIdentity(claims, "Bearer");
        context.User = new ClaimsPrincipal(identity);
        return context;
    }

    private void SetupTenantContext(string identifier)
    {
        var tenant = new IdmtTenantInfo("id", identifier, "Test");
        var multiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(multiTenantContext);
    }
}
