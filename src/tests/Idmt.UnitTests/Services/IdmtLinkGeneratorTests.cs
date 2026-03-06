using System.Text;
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
    public void GenerateConfirmEmailLink_ServerConfirm_UsesLinkGenerator()
    {
        const string email = "user@example.com";
        const string token = "confirm-token";
        const string expectedUrl = "https://demo.example/confirm-email";
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ServerConfirm;

        var expectedEncodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        RouteValueDictionary? capturedRouteValues = null;
        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                IdmtEndpointNames.ConfirmEmailDirect,
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

        var result = _service.GenerateConfirmEmailLink(email, token);

        Assert.Equal(expectedUrl, result);
        Assert.NotNull(capturedRouteValues);
        Assert.Equal(email, capturedRouteValues!["email"]?.ToString());
        Assert.Equal(expectedEncodedToken, capturedRouteValues["token"]?.ToString());
        Assert.Equal(_tenantInfo.Identifier, capturedRouteValues["tenantIdentifier"]?.ToString());
    }

    [Fact]
    public void GenerateConfirmEmailLink_ClientForm_ReturnsClientUri()
    {
        const string email = "user@example.com";
        const string token = "confirm-token";
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ConfirmEmailFormPath = "/confirm-email";

        var result = _service.GenerateConfirmEmailLink(email, token);
        var uri = new Uri(result);

        var expectedBase = $"{_options.Application.ClientUrl!.TrimEnd('/')}/{_options.Application.ConfirmEmailFormPath!.TrimStart('/')}";
        Assert.Equal(expectedBase, uri.GetLeftPart(UriPartial.Path));

        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal(_tenantInfo.Identifier, query["tenantIdentifier"].ToString());
        Assert.Equal(email, query["email"].ToString());

        // Token should be Base64URL-encoded
        var encodedToken = query["token"].ToString();
        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encodedToken));
        Assert.Equal(token, decodedToken);
    }

    [Fact]
    public void GeneratePasswordResetLink_ReturnsClientUri()
    {
        const string email = "user@example.com";
        const string token = "reset-token";
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ResetPasswordFormPath = "/reset-password";

        var result = _service.GeneratePasswordResetLink(email, token);
        var uri = new Uri(result);

        var expectedBase = $"{_options.Application.ClientUrl!.TrimEnd('/')}/{_options.Application.ResetPasswordFormPath!.TrimStart('/')}";
        Assert.Equal(expectedBase, uri.GetLeftPart(UriPartial.Path));

        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal(_tenantInfo.Identifier, query["tenantIdentifier"].ToString());
        Assert.Equal(email, query["email"].ToString());

        // Token should be Base64URL-encoded
        var encodedToken = query["token"].ToString();
        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encodedToken));
        Assert.Equal(token, decodedToken);
    }

    [Fact]
    public void GenerateConfirmEmailLink_ThrowsWhenHttpContextMissing()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GenerateConfirmEmailLink("user@example.com", "token"));

        Assert.Equal("No HTTP context was found.", exception.Message);
    }

    [Fact]
    public void GenerateConfirmEmailLink_ClientForm_ThrowsWhenClientUrlMissing()
    {
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;

        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GenerateConfirmEmailLink("user@example.com", "token"));

        Assert.Equal("Client URL is not configured.", exception.Message);
    }

    [Fact]
    public void GenerateConfirmEmailLink_ServerConfirm_ThrowsWhenEndpointNotFound()
    {
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ServerConfirm;

        _linkGeneratorMock.Setup(x => x.GetUriByAddress<string>(
                _httpContext,
                IdmtEndpointNames.ConfirmEmailDirect,
                It.IsAny<RouteValueDictionary>(),
                It.IsAny<RouteValueDictionary?>(),
                It.IsAny<string?>(),
                It.IsAny<HostString?>(),
                It.IsAny<PathString?>(),
                It.IsAny<FragmentString>(),
                It.IsAny<LinkOptions?>()))
            .Returns((string?)null);

        var exception = Assert.Throws<NotSupportedException>(() =>
            _service.GenerateConfirmEmailLink("user@example.com", "token"));

        Assert.Contains(IdmtEndpointNames.ConfirmEmailDirect, exception.Message);
    }

    [Fact]
    public void GeneratePasswordResetLink_ThrowsWhenHttpContextMissing()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GeneratePasswordResetLink("user@example.com", "token"));

        Assert.Equal("No HTTP context was found.", exception.Message);
    }

    [Fact]
    public void GeneratePasswordResetLink_ThrowsWhenClientUrlMissing()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            _service.GeneratePasswordResetLink("user@example.com", "token"));

        Assert.Equal("Client URL is not configured.", exception.Message);
    }

    [Fact]
    public void GenerateConfirmEmailLink_Base64UrlEncodesSpecialCharacterTokens()
    {
        // Tokens from Identity often contain +, /, = which need Base64URL encoding
        const string token = "CfDJ8N+test/token=value==";
        _options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        _options.Application.ClientUrl = "https://client.example";
        _options.Application.ConfirmEmailFormPath = "/confirm-email";

        var result = _service.GenerateConfirmEmailLink("user@example.com", token);
        var uri = new Uri(result);
        var query = QueryHelpers.ParseQuery(uri.Query);

        var encodedToken = query["token"].ToString();
        // Should not contain raw +, /, = (Base64URL uses -, _, no padding)
        Assert.DoesNotContain("+", encodedToken);
        Assert.DoesNotContain("/", encodedToken);

        // Decoding should return the original token
        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encodedToken));
        Assert.Equal(token, decodedToken);
    }
}
