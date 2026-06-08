using System.Net;
using System.Net.Http.Headers;

namespace Idmt.AspNetCore.Tests.MultiTenancy;

/// <summary>
/// Proves the per-request audience binding and the refresh audience precedence rule
/// against the real OpenIddict pipeline. Maps to the acceptance criteria in
/// docs/v2/05-multitenancy-audience.md: cross-tenant 401, same-tenant 200, and a
/// tenant-A refresh token cannot mint a tenant-B access token.
/// </summary>
public sealed class TenantAudienceHandlerTests(TenantAudienceTestHost host)
    : IClassFixture<TenantAudienceTestHost>
{
    [Fact]
    public async Task TokenForTenantA_OnTenantBRoute_Returns401()
    {
        var (accessToken, _) = await host.GetTokensAsync(TenantAudienceTestHost.TenantA);

        var response = await WhoAmIAsync(accessToken, resolvedTenant: TenantAudienceTestHost.TenantB);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenForTenantA_OnTenantARoute_Returns200()
    {
        // Also pins the middleware order: Finbuckle must resolve the tenant before
        // authentication, or the same-tenant request would fail.
        var (accessToken, _) = await host.GetTokensAsync(TenantAudienceTestHost.TenantA);

        var response = await WhoAmIAsync(accessToken, resolvedTenant: TenantAudienceTestHost.TenantA);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RefreshTokenForTenantA_WithResourceTenantB_IsRejected()
    {
        // The headline cross-tenant escalation: a tenant-A refresh token cannot mint a
        // tenant-B access token. The engine's native ValidateResources rejects the stray
        // tenant resource (tenant URNs are scopes, never static resources); the §2.9 startup
        // guard keeps that invariant true (see TenantResourceRegistrationGuardTests).
        var (_, refreshToken) = await host.GetTokensAsync(TenantAudienceTestHost.TenantA);

        var response = await host.RefreshAsync(
            refreshToken,
            resource: Idmt.AspNetCore.MultiTenancy.TenantUrns.For(TenantAudienceTestHost.TenantB));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithNoResolvedTenant_Returns401()
    {
        // Fail closed: a valid token on a resource route with no tenant resolved is rejected
        // rather than waved through. Pins the no-tenant branch of the audience handler.
        var (accessToken, _) = await host.GetTokensAsync(TenantAudienceTestHost.TenantA);

        var response = await WhoAmIAsync(accessToken, resolvedTenant: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenWithNoTenantAudience_Returns401()
    {
        // A token carrying no tenant URN in its aud must never satisfy the binding.
        var accessToken = await host.GetAccessTokenForScopeAsync("offline_access");

        var response = await WhoAmIAsync(accessToken, resolvedTenant: TenantAudienceTestHost.TenantA);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(TenantAudienceTestHost.TenantA)]
    [InlineData(TenantAudienceTestHost.TenantB)]
    public async Task TokenBoundToTwoTenants_Returns401_OnEitherRoute(string resolvedTenant)
    {
        // Exclusivity: a token whose aud carries BOTH tenant URNs must be rejected on both
        // routes, not accepted on either. A membership check would wrongly accept it.
        var accessToken = await host.GetAccessTokenForScopeAsync(
            $"{Idmt.AspNetCore.MultiTenancy.TenantUrns.For(TenantAudienceTestHost.TenantA)} " +
            $"{Idmt.AspNetCore.MultiTenancy.TenantUrns.For(TenantAudienceTestHost.TenantB)} offline_access");

        var response = await WhoAmIAsync(accessToken, resolvedTenant);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RefreshTokenForTenantA_WithNoResource_Succeeds()
    {
        // A plain refresh (no resource override) reuses the original tenant binding and
        // passes through the precedence handler untouched.
        var (_, refreshToken) = await host.GetTokensAsync(TenantAudienceTestHost.TenantA);

        var response = await host.RefreshAsync(refreshToken);

        response.EnsureSuccessStatusCode();
    }

    private async Task<HttpResponseMessage> WhoAmIAsync(string accessToken, string? resolvedTenant)
    {
        var client = host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/whoami");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (resolvedTenant is not null)
        {
            request.Headers.Add("X-Tenant", resolvedTenant);
        }

        return await client.SendAsync(request);
    }
}
