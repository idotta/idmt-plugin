using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Idmt.UnitTests;

public class IdmtLinkGeneratorTests
{
    private readonly Mock<LinkGenerator> _linkGeneratorMock;
    private readonly Mock<IMultiTenantContextAccessor> _multiTenantContextAccessorMock;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private readonly Mock<IOptions<IdmtOptions>> _optionsMock;
    private readonly Mock<ILogger<IdmtLinkGenerator>> _loggerMock;
    private readonly IdmtLinkGenerator _service;

    public IdmtLinkGeneratorTests()
    {
        _linkGeneratorMock = new Mock<LinkGenerator>();
        _multiTenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _optionsMock = new Mock<IOptions<IdmtOptions>>();
        _loggerMock = new Mock<ILogger<IdmtLinkGenerator>>();

        _optionsMock.Setup(x => x.Value).Returns(new IdmtOptions());

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
}
