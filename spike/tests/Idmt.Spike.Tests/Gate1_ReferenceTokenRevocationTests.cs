using System.Net;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 1: reference tokens with EnableTokenEntryValidation revoke on the next
/// request through the local validation handler.
/// </summary>
public sealed class Gate1_ReferenceTokenRevocationTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public async Task RevokedReferenceToken_Returns401_OnNextRequest()
    {
        var token = await GetClientTokenAsync(IdmtSpikeSeeder.TenantA);
        var client = ClientForTenant(IdmtSpikeSeeder.TenantA, token);

        // Valid before revocation.
        var before = await client.GetAsync("/api/whoami");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        // Revoke the token entry server-side (single row status update).
        using (var scope = Factory.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            await foreach (var entry in manager.FindBySubjectAsync(IdmtSpikeSeeder.ClientId))
            {
                await manager.TryRevokeAsync(entry);
            }
        }

        // Rejected on the next request, before the token's TTL expires.
        var after = await client.GetAsync("/api/whoami");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }
}
