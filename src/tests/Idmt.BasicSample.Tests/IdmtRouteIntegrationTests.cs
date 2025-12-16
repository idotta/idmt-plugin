using System.Net;
using System.Net.Http.Json;
using Idmt.Plugin.Configuration;

namespace Idmt.BasicSample.Tests;

public sealed class IdmtRouteIntegrationTests : IDisposable
{
    private readonly IdmtApiFactory _factory;

    public IdmtRouteIntegrationTests()
    {
        _factory = new IdmtApiFactory([
            IdmtMultiTenantStrategy.Route
        ]);
    }

    public void Dispose()
    {
        _factory.Dispose();
    }

    [Fact]
    public async Task Auth_login_via_route_strategy()
    {
        var client = _factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("auth/login?useCookies=true", new
        {
            EmailOrUsername = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });

        await loginResponse.AssertSuccess();
    }

    [Fact]
    public async Task Endpoints_are_not_accessible_at_root()
    {
        // When route strategy is enabled, endpoints are moved to /{tenant}/...
        // So root endpoints should not exist (404)
        var client = _factory.CreateClient(); // No tenant, no route base address

        var response = await client.GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Healthz_accessible_via_route()
    {
        var client = _factory.CreateClientWithTenant();

        // We need to authenticate first for healthz usually, but let's check if it's found at least
        // The original test says Healthz_requires_authentication returns Unauthorized/Forbidden/Found

        var response = await client.GetAsync("healthz");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found, HttpStatusCode.OK });
        Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }
}