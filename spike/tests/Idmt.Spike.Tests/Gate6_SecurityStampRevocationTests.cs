using Idmt.Spike.Host.Seeding;
using Idmt.Spike.Host.Server;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 6: the SecurityStamp-change revocation hook. All-user revoke drops every
/// token the user holds; single-tenant revoke drops only that tenant's tokens —
/// expressed by per-(subject, tenant) authorization grouping, since a token entry
/// records no audience to filter on. Tokens are minted directly through the token
/// manager (status-checkable, not bearer-validatable), so the assertions read
/// <c>GetStatusAsync</c> rather than round-tripping a bearer request.
/// </summary>
public sealed class Gate6_SecurityStampRevocationTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public async Task RevokeAllForUser_DropsEveryTokenAcrossTenants_AtBoundedCost()
    {
        // A fresh synthetic subject keeps this test independent of the others.
        var subject = Guid.NewGuid().ToString();

        // "Many tokens": 60 for acme, 40 for globex.
        await MintAsync(subject, IdmtSpikeSeeder.TenantA, 60);
        await MintAsync(subject, IdmtSpikeSeeder.TenantB, 40);
        Assert.Equal(100, await CountAsync(subject));

        using (var scope = Factory.Services.CreateScope())
        {
            var hook = scope.ServiceProvider.GetRequiredService<TokenRevocationHook>();
            // RevokeBySubjectAsync is a single store call: cost does not scale with
            // the number of tokens the user holds (the property item 6 names).
            var revoked = await hook.RevokeAllForUserAsync(subject, default);
            Assert.Equal(100, revoked);
        }

        var statuses = await StatusesAsync(subject);
        Assert.Equal(100, statuses.Count);
        Assert.All(statuses, s => Assert.Equal(Statuses.Revoked, s, ignoreCase: true));
    }

    [Fact]
    public async Task RevokeForUserTenant_DropsOnlyThatTenant()
    {
        var subject = Guid.NewGuid().ToString();
        await MintAsync(subject, IdmtSpikeSeeder.TenantA, 5);
        await MintAsync(subject, IdmtSpikeSeeder.TenantB, 5);

        using (var scope = Factory.Services.CreateScope())
        {
            var hook = scope.ServiceProvider.GetRequiredService<TokenRevocationHook>();
            var revoked = await hook.RevokeForUserTenantAsync(subject, IdmtSpikeSeeder.TenantA, default);
            Assert.True(revoked);
        }

        var byTenant = await StatusesByTenantAsync(subject);
        Assert.All(byTenant[IdmtSpikeSeeder.TenantA], s => Assert.Equal(Statuses.Revoked, s, ignoreCase: true));
        Assert.All(byTenant[IdmtSpikeSeeder.TenantB], s => Assert.Equal(Statuses.Valid, s, ignoreCase: true));
    }

    private async Task MintAsync(string subject, string tenant, int count)
    {
        using var scope = Factory.Services.CreateScope();
        var mint = scope.ServiceProvider.GetRequiredService<UserTokenMint>();
        for (var i = 0; i < count; i++)
        {
            await mint.MintAsync(subject, tenant, default);
        }
    }

    private async Task<int> CountAsync(string subject)
    {
        using var scope = Factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var n = 0;
        await foreach (var _ in tokens.FindBySubjectAsync(subject, default))
        {
            n++;
        }

        return n;
    }

    private async Task<List<string>> StatusesAsync(string subject)
    {
        using var scope = Factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var statuses = new List<string>();
        await foreach (var token in tokens.FindBySubjectAsync(subject, default))
        {
            statuses.Add((await tokens.GetStatusAsync(token, default))!);
        }

        return statuses;
    }

    private async Task<Dictionary<string, List<string>>> StatusesByTenantAsync(string subject)
    {
        using var scope = Factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

        // Map each (subject, tenant) authorization id back to its tenant via the marker scope.
        var tenantByAuthId = new Dictionary<string, string>(StringComparer.Ordinal);
        await foreach (var authorization in authorizations.FindBySubjectAsync(subject, default))
        {
            var id = (await authorizations.GetIdAsync(authorization, default))!;
            var scopes = await authorizations.GetScopesAsync(authorization, default);
            var marker = scopes.FirstOrDefault(s => s.StartsWith("idmt:authz:tenant:", StringComparison.Ordinal));
            if (marker is not null)
            {
                tenantByAuthId[id] = marker["idmt:authz:tenant:".Length..];
            }
        }

        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        await foreach (var token in tokens.FindBySubjectAsync(subject, default))
        {
            var authId = await tokens.GetAuthorizationIdAsync(token, default);
            if (authId is null || !tenantByAuthId.TryGetValue(authId, out var tenant))
            {
                continue;
            }

            var status = (await tokens.GetStatusAsync(token, default))!;
            (result.TryGetValue(tenant, out var list) ? list : result[tenant] = []).Add(status);
        }

        return result;
    }
}
