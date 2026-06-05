using System.Net;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 3: the IDMT-owned per-request audience handler rejects a token whose
/// audience does not equal the Finbuckle-resolved tenant.
/// </summary>
public sealed class Gate3_AudienceHandlerTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public async Task TokenForTenantA_OnTenantBRoute_IsRejected()
    {
        var tokenForA = await GetClientTokenAsync(IdmtSpikeSeeder.TenantA);

        // Same token, but the request resolves to tenant B.
        var crossTenant = ClientForTenant(IdmtSpikeSeeder.TenantB, tokenForA);
        var response = await crossTenant.GetAsync("/api/whoami");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenForTenantA_OnTenantARoute_IsAccepted()
    {
        var tokenForA = await GetClientTokenAsync(IdmtSpikeSeeder.TenantA);

        var sameTenant = ClientForTenant(IdmtSpikeSeeder.TenantA, tokenForA);
        var response = await sameTenant.GetAsync("/api/whoami");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
