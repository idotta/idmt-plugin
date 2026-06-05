using System.Net.Http.Json;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 4 (the ADR's first item): OpenIddict's EF stores in a separate,
/// tenant-agnostic DbContext coexist with Finbuckle save-side TenantId stamping,
/// and the token endpoint reads/writes tokens with no ambient tenant.
/// </summary>
public sealed class Gate4_DualContextCompositionTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public async Task TokenEndpoint_IssuesAndPersistsToken_WithNoAmbientTenant()
    {
        // The token request carries NO X-Tenant header: no ambient tenant.
        var token = await GetClientTokenAsync(IdmtSpikeSeeder.TenantA);
        Assert.False(string.IsNullOrWhiteSpace(token));

        // The reference token was persisted to the tenant-agnostic OpenIddict store.
        using var scope = Factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var count = await manager.CountAsync();
        Assert.True(count > 0, "Expected at least one persisted OpenIddict token entry.");
    }

    [Fact]
    public async Task FinbuckleStampsAppEntity_WhileOpenIddictTablesStayTenantAgnostic()
    {
        // Finbuckle stamps the app entity's TenantId (the tenant's Id) on save
        // under the ambient tenant.
        var client = ClientForTenant(IdmtSpikeSeeder.TenantA);
        var response = await client.PostAsync($"/api/widgets?label=alpha", content: null);
        response.EnsureSuccessStatusCode();
        var widget = await response.Content.ReadFromJsonAsync<WidgetDto>();

        using var scope = Factory.Services.CreateScope();
        var store = scope.ServiceProvider
            .GetRequiredService<Finbuckle.MultiTenant.Abstractions.IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(IdmtSpikeSeeder.TenantA);
        Assert.False(string.IsNullOrEmpty(widget!.TenantId));
        Assert.Equal(tenant!.Id, widget.TenantId);

        // The OpenIddict token table has no TenantId concept: its model has no such property.
        var oidb = scope.ServiceProvider.GetRequiredService<IdmtOpenIddictDbContext>();
        var tokenEntityType = oidb.Model.GetEntityTypes()
            .Single(t => t.ClrType.Name.StartsWith("OpenIddictEntityFrameworkCoreToken", StringComparison.Ordinal));
        Assert.Null(tokenEntityType.FindProperty("TenantId"));
    }

    private sealed record WidgetDto(Guid Id, string TenantId);
}
