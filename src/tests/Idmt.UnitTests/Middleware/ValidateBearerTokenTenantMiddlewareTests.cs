using System.Security.Claims;
using System.Text.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
    public async Task InvokeAsync_MissingTenantClaim_Returns401WithProblemDetails()
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
        AssertProblemDetailsResponse(context, StatusCodes.Status401Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task InvokeAsync_MismatchedTenantClaim_Returns403WithProblemDetails()
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
        AssertProblemDetailsResponse(context, StatusCodes.Status403Forbidden, "Forbidden");
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
    public async Task InvokeAsync_ExceptionInValidation_Returns401WithProblemDetails()
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
        AssertProblemDetailsResponse(context, StatusCodes.Status401Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task InvokeAsync_EmptyStringTenantClaim_Returns401WithProblemDetails()
    {
        // Empty string tenant claim should be treated the same as missing
        var context = CreateBearerContext(tenantClaimValue: "", claimKey: null);
        SetupTenantContext("test-tenant");

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        AssertProblemDetailsResponse(context, StatusCodes.Status401Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task InvokeAsync_UsesCustomClaimType_WhenConfigured()
    {
        // Configure a custom claim type
        const string customClaimType = "custom_tenant_claim";
        _options.MultiTenant.StrategyOptions[IdmtMultiTenantStrategy.Claim] = customClaimType;

        var context = CreateBearerContext(tenantClaimValue: "test-tenant", claimKey: customClaimType);
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
    public async Task InvokeAsync_Returns403_WhenTenantClaimCaseDiffers()
    {
        // Ordinal comparison means different casing should fail
        var context = CreateBearerContext(tenantClaimValue: "Test-Tenant");
        SetupTenantContext("test-tenant");

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        AssertProblemDetailsResponse(context, StatusCodes.Status403Forbidden, "Forbidden");
    }

    [Fact]
    public async Task InvokeAsync_NullTenantContext_Returns401WithProblemDetails()
    {
        // No tenant context set at all (accessor returns null MultiTenantContext)
        var context = CreateBearerContext(tenantClaimValue: "test-tenant");
        _tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(default(IMultiTenantContext)!);

        var nextCalled = false;
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        AssertProblemDetailsResponse(context, StatusCodes.Status401Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task InvokeAsync_ErrorResponse_HasProblemJsonContentType()
    {
        var context = CreateBearerContext(tenantClaimValue: "tenant-a");
        SetupTenantContext("tenant-b");

        await _middleware.InvokeAsync(context, _ => Task.CompletedTask);

        Assert.Contains("application/problem+json", context.Response.ContentType);
    }

    [Fact]
    public async Task InvokeAsync_ErrorResponse_BodyContainsNonNullDetail()
    {
        var context = CreateBearerContext(tenantClaimValue: "tenant-a");
        SetupTenantContext("tenant-b");

        await _middleware.InvokeAsync(context, _ => Task.CompletedTask);

        var problem = ReadProblemDetails(context);
        Assert.NotNull(problem);
        Assert.False(string.IsNullOrWhiteSpace(problem.Detail));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private DefaultHttpContext CreateBearerContext(string? tenantClaimValue, string? claimKey = null)
    {
        // Use a real MemoryStream so WriteAsJsonAsync can write to the body
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Headers.Authorization = "Bearer test-token";

        var resolvedClaimKey = claimKey ?? _options.MultiTenant.StrategyOptions.GetValueOrDefault(
            IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim);

        var claims = new List<Claim> { new(ClaimTypes.Name, "user") };
        if (tenantClaimValue != null)
        {
            claims.Add(new Claim(resolvedClaimKey, tenantClaimValue));
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

    /// <summary>
    /// Rewinds the response body stream and deserializes the ProblemDetails payload.
    /// Returns null when the body is empty.
    /// </summary>
    private static ProblemDetails? ReadProblemDetails(DefaultHttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var json = new StreamReader(context.Response.Body).ReadToEnd();
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<ProblemDetails>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    /// <summary>
    /// Asserts that the response body contains a valid ProblemDetails document with the
    /// expected status code and title, and that the Content-Type is application/problem+json.
    /// </summary>
    private static void AssertProblemDetailsResponse(
        DefaultHttpContext context,
        int expectedStatus,
        string expectedTitle)
    {
        Assert.Contains("application/problem+json", context.Response.ContentType);

        var problem = ReadProblemDetails(context);
        Assert.NotNull(problem);
        Assert.Equal(expectedStatus, problem.Status);
        Assert.Equal(expectedTitle, problem.Title);
        Assert.False(string.IsNullOrWhiteSpace(problem.Detail),
            "ProblemDetails.Detail must not be empty so API clients can diagnose the failure.");
    }
}
