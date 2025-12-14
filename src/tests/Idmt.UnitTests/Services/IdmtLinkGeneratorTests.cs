using System;
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
using Xunit;

namespace Idmt.UnitTests.Services;

public class IdmtLinkGeneratorTests
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

    public IdmtLinkGeneratorTests()
    {
        _linkGeneratorMock = new Mock<LinkGenerator>();
        _multiTenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _multiTenantContextMock = new Mock<IMultiTenantContext>();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _optionsMock = new Mock<IOptions<IdmtOptions>>();
        _loggerMock = new Mock<ILogger<IdmtLinkGenerator>>();
        _options = new IdmtOptions();
        _tenantInfo = new IdmtTenantInfo { Id = "tenant-1" };
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
    public void Constructor_ShouldInitialize()
    {
        Assert.NotNull(_service);
    }

    [Fact]
    public void GenerateConfirmEmailApiLink_UsesLinkGenerator()
    {
        const string email = "user@example.com";
        const string token = "confirm-token";
        const string expectedUrl = "https://demo.example/confirm-email";

        RouteValueDictionary? capturedRouteValues = null;
        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                ApplicationOptions.ConfirmEmailEndpointName,
                It.IsAny<RouteValueDictionary>(),
                It.IsAny<RouteValueDictionary?>(),
                It.IsAny<string?>(),
                It.IsAny<HostString?>(),
                It.IsAny<PathString?>(),
                It.IsAny<FragmentString>(),
                It.IsAny<LinkOptions?>()))
            .Callback<HttpContext, string, RouteValueDictionary, RouteValueDictionary?, string?, HostString?, PathString?, FragmentString, LinkOptions?>((context, name, values, ambientValues, scheme, host, pathBase, fragment, options) =>
            {
                capturedRouteValues = values;
            })
            .Returns(expectedUrl);

        var result = _service.GenerateConfirmEmailApiLink(email, token);

        Assert.Equal(expectedUrl, result);
        Assert.NotNull(capturedRouteValues);
        Assert.True(HasExpectedRouteValues(capturedRouteValues!, _tenantInfo.Id ?? string.Empty, email, token));
    }

    [Fact]
    public void GeneratePasswordResetApiLink_UsesLinkGenerator()
    {
        const string email = "user@example.com";
        const string token = "reset-token";
        const string expectedUrl = "https://demo.example/password-reset";

        RouteValueDictionary? capturedRouteValues = null;
        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                ApplicationOptions.PasswordResetEndpointName,
                It.IsAny<RouteValueDictionary>(),
                It.IsAny<RouteValueDictionary?>(),
                It.IsAny<string?>(),
                It.IsAny<HostString?>(),
                It.IsAny<PathString?>(),
                It.IsAny<FragmentString>(),
                It.IsAny<LinkOptions?>()))
            .Callback<HttpContext, string, RouteValueDictionary, RouteValueDictionary?, string?, HostString?, PathString?, FragmentString, LinkOptions?>((context, name, values, ambientValues, scheme, host, pathBase, fragment, options) =>
            {
                capturedRouteValues = values;
            })
            .Returns(expectedUrl);

        var result = _service.GeneratePasswordResetApiLink(email, token);

        Assert.Equal(expectedUrl, result);
        Assert.NotNull(capturedRouteValues);
        Assert.True(HasExpectedRouteValues(capturedRouteValues!, _tenantInfo.Id ?? string.Empty, email, token));
    }

    [Fact]
    public void GenerateConfirmEmailFormLink_ReturnsClientUri()
    {
        const string email = "user@example.com";
        const string token = "confirm-token";
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ConfirmEmailFormPath = "/confirm-email";

        var result = _service.GenerateConfirmEmailFormLink(email, token);
        var uri = new Uri(result);

        var expectedBase = $"{_options.Application.ClientUrl!.TrimEnd('/')}/{_options.Application.ConfirmEmailFormPath!.TrimStart('/')}";
        Assert.Equal(expectedBase, uri.GetLeftPart(UriPartial.Path));

        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal(_tenantInfo.Id, query["tenantId"].ToString());
        Assert.Equal(email, query["email"].ToString());
        Assert.Equal(token, query["token"].ToString());
    }

    [Fact]
    public void GeneratePasswordResetFormLink_ReturnsClientUri()
    {
        const string email = "user@example.com";
        const string token = "reset-token";
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ResetPasswordFormPath = "/reset-password";

        var result = _service.GeneratePasswordResetFormLink(email, token);
        var uri = new Uri(result);

        var expectedBase = $"{_options.Application.ClientUrl!.TrimEnd('/')}/{_options.Application.ResetPasswordFormPath!.TrimStart('/')}";
        Assert.Equal(expectedBase, uri.GetLeftPart(UriPartial.Path));

        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal(_tenantInfo.Id, query["tenantId"].ToString());
        Assert.Equal(email, query["email"].ToString());
        Assert.Equal(token, query["token"].ToString());
    }

    [Fact]
    public void GenerateConfirmEmailApiLink_ThrowsWhenHttpContextMissing()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GenerateConfirmEmailApiLink("user@example.com", "token"));

        Assert.Equal("No HTTP context was found.", exception.Message);
    }

    [Fact]
    public void GenerateConfirmEmailFormLink_ThrowsWhenClientUrlMissing()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GenerateConfirmEmailFormLink("user@example.com", "token"));

        Assert.Equal("Client URL is not configured.", exception.Message);
    }

    [Fact]
    public void GenerateConfirmEmailApiLink_ThrowsWhenEndpointNotFound()
    {
        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                ApplicationOptions.ConfirmEmailEndpointName,
                It.IsAny<RouteValueDictionary>(),
                It.IsAny<RouteValueDictionary?>(),
                It.IsAny<string?>(),
                It.IsAny<HostString?>(),
                It.IsAny<PathString?>(),
                It.IsAny<FragmentString>(),
                It.IsAny<LinkOptions?>()))
            .Returns((string?)null);

        var exception = Assert.Throws<NotSupportedException>(() =>
            _service.GenerateConfirmEmailApiLink("user@example.com", "token"));

        Assert.Contains(ApplicationOptions.ConfirmEmailEndpointName, exception.Message);
    }

    [Fact]
    public void GeneratePasswordResetApiLink_ThrowsWhenEndpointNotFound()
    {
        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                ApplicationOptions.PasswordResetEndpointName,
                It.IsAny<RouteValueDictionary>(),
                It.IsAny<RouteValueDictionary?>(),
                It.IsAny<string?>(),
                It.IsAny<HostString?>(),
                It.IsAny<PathString?>(),
                It.IsAny<FragmentString>(),
                It.IsAny<LinkOptions?>()))
            .Returns((string?)null);

        var exception = Assert.Throws<NotSupportedException>(() =>
            _service.GeneratePasswordResetApiLink("user@example.com", "token"));

        Assert.Contains(ApplicationOptions.PasswordResetEndpointName, exception.Message);
    }

    [Fact]
    public void GeneratePasswordResetApiLink_ThrowsWhenHttpContextMissing()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GeneratePasswordResetApiLink("user@example.com", "token"));

        Assert.Equal("No HTTP context was found.", exception.Message);
    }

    [Fact]
    public void GeneratePasswordResetFormLink_ThrowsWhenClientUrlMissing()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GeneratePasswordResetFormLink("user@example.com", "token"));

        Assert.Equal("Client URL is not configured.", exception.Message);
    }

    private static bool HasExpectedRouteValues(RouteValueDictionary routeValues, string tenantId, string email, string token)
    {
        return routeValues.TryGetValue("tenantId", out var tenantValue)
            && routeValues.TryGetValue("email", out var emailValue)
            && routeValues.TryGetValue("token", out var tokenValue)
            && string.Equals(tenantValue?.ToString(), tenantId, StringComparison.Ordinal)
            && string.Equals(emailValue?.ToString(), email, StringComparison.Ordinal)
            && string.Equals(tokenValue?.ToString(), token, StringComparison.Ordinal);
    }
}
