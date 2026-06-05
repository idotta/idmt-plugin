using System.Net;
using System.Net.Http.Json;
using Idmt.Spike.Host.Bff;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 7: a BFF session. The browser holds only an opaque session-id cookie; the
/// host resolves it server-side to a reference token and runs it through the SAME
/// audience handler a raw bearer request runs. A mutating request without an
/// anti-forgery token is rejected.
/// </summary>
public sealed class Gate7_BffSessionTests(Gate7Factory factory) : IClassFixture<Gate7Factory>
{
    private readonly Gate7Factory _factory = factory;

    [Fact]
    public async Task Login_SetsHttpOnlyCookie_AndKeepsTokenServerSideOnly()
    {
        var client = _factory.CreateClient();
        var response = await LoginAsync(client, IdmtSpikeSeeder.TenantA);
        response.EnsureSuccessStatusCode();

        // The browser-facing response carries no access/refresh token.
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("access_token", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refresh_token", body, StringComparison.OrdinalIgnoreCase);

        // The session cookie is httpOnly and is NOT the token: the token lives only
        // in the server-side session store.
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"),
            c => c.StartsWith(BffEndpoints.CookieName + "=", StringComparison.Ordinal));
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);

        var cookieValue = setCookie.Split(';')[0][(BffEndpoints.CookieName.Length + 1)..];

        // Decode the cookie to the session id, then read the server-side session:
        // the cookie is a protected session id (GUID "N"), and the actual reference
        // token lives only in the store — it appears in neither the cookie nor the
        // response body. This is the real "no token in the browser" proof.
        var protector = _factory.Services
            .GetRequiredService<IDataProtectionProvider>().CreateProtector(BffEndpoints.ProtectorPurpose);
        var sessionId = protector.Unprotect(cookieValue);
        var session = _factory.Services.GetRequiredService<IBffSessionStore>().Get(sessionId);

        Assert.NotNull(session);
        Assert.False(string.IsNullOrEmpty(session!.ReferenceToken));
        Assert.NotEqual(session.ReferenceToken, cookieValue);
        Assert.DoesNotContain(session.ReferenceToken, cookieValue, StringComparison.Ordinal);
        Assert.DoesNotContain(session.ReferenceToken, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CookieRequest_RunsSameAudienceHandler_AcceptsHomeTenant_RejectsOther()
    {
        var client = _factory.CreateClient();
        var login = await LoginAsync(client, IdmtSpikeSeeder.TenantA);
        login.EnsureSuccessStatusCode();

        // Same client (shared cookie container) carries the bff_session cookie.
        // acme-resolved request: the session token's audience matches -> 200.
        var ok = await client.SendAsync(WhoAmI(IdmtSpikeSeeder.TenantA));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        // globex-resolved request: same cookie, same validation, audience mismatch
        // -> 401 from the very handler a raw bearer request hits (gate 3).
        var rejected = await client.SendAsync(WhoAmI(IdmtSpikeSeeder.TenantB));
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    [Fact]
    public async Task MutatingRequest_WithoutAntiforgeryToken_IsRejected_WithToken_Succeeds()
    {
        var client = _factory.CreateClient();
        var login = await LoginAsync(client, IdmtSpikeSeeder.TenantA);
        login.EnsureSuccessStatusCode();
        var csrf = await GetCsrfAsync(client);

        // Cookie present (auth passes via the resolver) but NO anti-forgery token.
        var missing = new HttpRequestMessage(HttpMethod.Post, "/bff/widgets?label=alpha");
        missing.Headers.Add("X-Tenant", IdmtSpikeSeeder.TenantA);
        var missingResponse = await client.SendAsync(missing);
        Assert.Equal(HttpStatusCode.BadRequest, missingResponse.StatusCode);

        // Same client, now echoing the anti-forgery request token -> success.
        var valid = new HttpRequestMessage(HttpMethod.Post, "/bff/widgets?label=beta");
        valid.Headers.Add("X-Tenant", IdmtSpikeSeeder.TenantA);
        valid.Headers.Add("X-CSRF-TOKEN", csrf);
        var validResponse = await client.SendAsync(valid);
        validResponse.EnsureSuccessStatusCode();
    }

    private static Task<HttpResponseMessage> LoginAsync(HttpClient client, string tenant) =>
        client.PostAsJsonAsync("/bff/login",
            new BffEndpoints.LoginRequest(IdmtSpikeSeeder.BffUserEmail, IdmtSpikeSeeder.BffUserPassword, tenant));

    private static async Task<string> GetCsrfAsync(HttpClient client)
    {
        // Carries X-Tenant so the session token resolves and authenticates (the
        // audience handler refuses a token-bound request with no resolved tenant).
        var request = new HttpRequestMessage(HttpMethod.Get, "/bff/csrf");
        request.Headers.Add("X-Tenant", IdmtSpikeSeeder.TenantA);
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BffEndpoints.CsrfResponse>())!.AntiforgeryToken;
    }

    private static HttpRequestMessage WhoAmI(string tenant)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/whoami");
        request.Headers.Add("X-Tenant", tenant);
        return request;
    }
}

/// <summary>
/// Routes the BFF self back-channel HttpClient at the in-memory TestServer, so
/// <c>/bff/login</c> can mint a real reference token from the co-hosted token
/// endpoint without leaving the process.
/// </summary>
public sealed class Gate7Factory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureTestServices(services =>
            services.AddHttpClient(BffBackChannel.Name)
                .ConfigurePrimaryHttpMessageHandler(() => Server.CreateHandler())
                .ConfigureHttpClient(c => c.BaseAddress = new Uri("http://localhost")));
}
