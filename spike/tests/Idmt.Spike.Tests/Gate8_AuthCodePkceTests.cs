using System.Net;
using System.Net.Http.Json;
using Idmt.Spike.Host.Bff;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 8: real browser login via authorization code + PKCE. The BFF drives the
/// flow, exchanges the code server-side, and stores the reference token in the
/// session — the browser holds only the opaque session cookie. The issued token's
/// subject is the authenticated USER (not the client), and it resolves through the
/// same tenant audience handler a raw bearer request uses. PKCE is enforced.
/// </summary>
public sealed class Gate8_AuthCodePkceTests(Gate7Factory factory) : IClassFixture<Gate7Factory>
{
    private readonly Gate7Factory _factory = factory;

    private HttpClient NoRedirectClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    [Fact]
    public async Task AuthCodePkce_IssuesUserSubjectToken_AndResolvesSession()
    {
        var client = NoRedirectClient();
        var userId = await UserIdAsync();

        await LoginAsync(client);
        await RunPkceFlowAsync(client, IdmtSpikeSeeder.TenantA);

        // The BFF session (bff_session cookie) resolves to the server-side token,
        // which validates through the OpenIddict pipeline + audience handler.
        var whoami = await client.SendAsync(WhoAmI(IdmtSpikeSeeder.TenantA));
        Assert.Equal(HttpStatusCode.OK, whoami.StatusCode);

        var body = await whoami.Content.ReadFromJsonAsync<WhoAmIResponse>();
        // The core proof: subject is the authenticated user, not the client.
        Assert.Equal(userId.ToString(), body!.Subject);
        Assert.NotEqual(IdmtSpikeSeeder.SpaClientId, body.Subject);
    }

    [Fact]
    public async Task BffSession_RunsSameAudienceHandler_RejectsOtherTenant()
    {
        var client = NoRedirectClient();
        await LoginAsync(client);
        await RunPkceFlowAsync(client, IdmtSpikeSeeder.TenantA);

        var acme = await client.SendAsync(WhoAmI(IdmtSpikeSeeder.TenantA));
        Assert.Equal(HttpStatusCode.OK, acme.StatusCode);

        var globex = await client.SendAsync(WhoAmI(IdmtSpikeSeeder.TenantB));
        Assert.Equal(HttpStatusCode.Unauthorized, globex.StatusCode);
    }

    [Fact]
    public async Task Authorize_WithoutPkceChallenge_IsRejected()
    {
        var client = NoRedirectClient();
        await LoginAsync(client);

        // A direct authorize request with no code_challenge: the public client
        // requires PKCE, so OpenIddict must refuse to issue a code.
        var url =
            "/connect/authorize?response_type=code" +
            $"&client_id={IdmtSpikeSeeder.SpaClientId}" +
            $"&redirect_uri={Uri.EscapeDataString(IdmtSpikeSeeder.SpaRedirectUri)}" +
            "&scope=api&state=nopkce";
        var response = await client.GetAsync(url);

        var location = response.Headers.Location?.ToString() ?? string.Empty;
        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest || location.Contains("error", StringComparison.Ordinal),
            $"Expected a PKCE rejection, got {(int)response.StatusCode} location='{location}'.");
    }

    // Drives /bff/login-pkce -> /connect/authorize -> /bff/callback, leaving the
    // bff_session cookie on the shared client. Asserts no token ever reaches the
    // browser (the redirect chain carries only code/state, never an access token).
    private static async Task RunPkceFlowAsync(HttpClient client, string tenant)
    {
        var start = await client.GetAsync($"/bff/login-pkce?tenant={tenant}");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var authorizeUrl = start.Headers.Location!.ToString();
        Assert.Contains("code_challenge=", authorizeUrl, StringComparison.Ordinal);

        var authorize = await client.GetAsync(authorizeUrl);
        Assert.True(authorize.StatusCode == HttpStatusCode.Redirect,
            $"authorize -> {(int)authorize.StatusCode}: {await authorize.Content.ReadAsStringAsync()} (url={authorizeUrl})");
        var callbackUrl = authorize.Headers.Location!.ToString();
        Assert.Contains("code=", callbackUrl, StringComparison.Ordinal);

        var callback = await client.GetAsync(callbackUrl);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        // The callback sets the session cookie and redirects to "/", carrying no token.
        Assert.DoesNotContain("access_token", callbackUrl, StringComparison.OrdinalIgnoreCase);
        var setCookie = string.Join(";", callback.Headers.TryGetValues("Set-Cookie", out var v) ? v : []);
        Assert.Contains(BffEndpoints.CookieName, setCookie, StringComparison.Ordinal);
    }

    private static async Task LoginAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/auth/login",
            new AuthServer.AuthLoginRequest(IdmtSpikeSeeder.BffUserEmail, IdmtSpikeSeeder.BffUserPassword));
        response.EnsureSuccessStatusCode();
    }

    private async Task<Guid> UserIdAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await users.FindByEmailAsync(IdmtSpikeSeeder.BffUserEmail);
        return user!.Id;
    }

    private static HttpRequestMessage WhoAmI(string tenant)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/whoami");
        request.Headers.Add("X-Tenant", tenant);
        return request;
    }

    private sealed record WhoAmIResponse(string Subject, string[] Audiences);
}
