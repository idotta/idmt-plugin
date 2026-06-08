using System.Net.Http.Json;
using System.Security.Claims;
using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.AspNetCore.MultiTenancy;
using Idmt.AspNetCore.Persistence;
using Idmt.AspNetCore.Server;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.AspNetCore.Tests.MultiTenancy;

/// <summary>
/// An in-process host that exercises the real audience-binding pipeline:
/// <see cref="MultiTenancyServiceCollectionExtensions.AddIdmtMultiTenancy"/> +
/// <see cref="OpenIddictServerServiceCollectionExtensions.AddIdmtOpenIddictServer"/>,
/// with Finbuckle resolving the tenant from the <c>X-Tenant</c> header before
/// authentication.
///
/// The seeder stands in for task 13: it registers each tenant's URN as an OpenIddict
/// scope whose <c>Resources</c> carry the same URN, so requesting that scope binds the
/// URN into the token's <c>aud</c> natively (no spike-style custom <c>tenant</c> field).
/// Two tenants are seeded (acme, globex) and one confidential client wired for the
/// authorization-code and refresh-token grants, which is the only way to obtain a
/// refresh token (client-credentials issues none).
/// </summary>
public sealed class TenantAudienceTestHost : IAsyncLifetime
{
    public const string ClientId = "test-client";
    public const string ClientSecret = "test-secret";
    public const string RedirectUri = "https://localhost/callback";
    public const string TenantA = "acme";
    public const string TenantB = "globex";

    private const string ServerScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    private SqliteConnection _oidcConnection = null!;
    private SqliteConnection _tenantConnection = null!;
    private IHost _host = null!;

    public IServiceProvider Services => _host.Services;

    public HttpClient CreateClient() => _host.GetTestClient();

    public async Task InitializeAsync()
    {
        _oidcConnection = new SqliteConnection("DataSource=:memory:");
        _oidcConnection.Open();
        _tenantConnection = new SqliteConnection("DataSource=:memory:");
        _tenantConnection.Open();

        _host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddDbContext<IdmtOpenIddictDbContext>(o =>
                    {
                        o.UseSqlite(_oidcConnection);
                        o.UseOpenIddict();
                    });
                    services.AddDbContext<IdmtTenantStoreDbContext>(o => o.UseSqlite(_tenantConnection));

                    services.AddIdmtMultiTenancy();

                    // Dev certs + HTTP transport live in the test, never in the library.
                    services.AddIdmtOpenIddictServer(configureServer: o =>
                    {
                        o.AddDevelopmentEncryptionCertificate();
                        o.AddDevelopmentSigningCertificate();
                        o.UseAspNetCore().DisableTransportSecurityRequirement();
                    });

                    services.AddRouting();
                });

                web.Configure(app =>
                {
                    app.UseRouting();
                    // Finbuckle must resolve the tenant BEFORE authentication so the
                    // audience handler can read the resolved tenant.
                    app.UseMultiTenant();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/connect/authorize", IssueAuthorizationCodeAsync);
                        endpoints.MapPost("/connect/token", ExchangeTokenAsync);
                        endpoints.MapGet("/whoami", () => Results.Ok("ok")).RequireAuthorization();
                    });
                });
            })
            .StartAsync();

        await SeedAsync();
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }

        _oidcConnection?.Dispose();
        _tenantConnection?.Dispose();
    }

    /// <summary>
    /// Runs the authorization-code flow for <paramref name="tenant"/> and returns the
    /// issued access and refresh tokens. The token's <c>aud</c> is bound to the tenant
    /// URN through the requested tenant scope.
    /// </summary>
    public Task<(string AccessToken, string RefreshToken)> GetTokensAsync(string tenant) =>
        AuthorizeAndExchangeAsync($"{TenantUrns.For(tenant)} offline_access");

    /// <summary>
    /// Runs the authorization-code flow requesting an arbitrary scope string and returns the
    /// access token. Used to mint edge-case tokens (no tenant scope, or two tenant scopes).
    /// </summary>
    public async Task<string> GetAccessTokenForScopeAsync(string scope) =>
        (await AuthorizeAndExchangeAsync(scope)).AccessToken;

    private async Task<(string AccessToken, string RefreshToken)> AuthorizeAndExchangeAsync(string scope)
    {
        var client = CreateClient();

        var authorizeUri = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = scope,
            ["state"] = "state",
        });

        var authorizeResponse = await client.GetAsync(authorizeUri);
        Assert.Equal(System.Net.HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location
            ?? throw new InvalidOperationException("The authorize endpoint did not redirect.");
        var code = QueryHelpers.ParseQuery(location.Query)["code"].ToString();
        Assert.False(string.IsNullOrEmpty(code), "No authorization code was returned.");

        var tokenResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
        }));

        tokenResponse.EnsureSuccessStatusCode();
        var payload = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>()
            ?? throw new InvalidOperationException("The token endpoint returned no payload.");

        return (payload.AccessToken!, payload.RefreshToken!);
    }

    /// <summary>Posts a refresh-token grant, optionally with a <c>resource</c> override.</summary>
    public async Task<HttpResponseMessage> RefreshAsync(string refreshToken, string? resource = null)
    {
        var client = CreateClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
        };

        if (resource is not null)
        {
            form["resource"] = resource;
        }

        return await client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
    }

    // Authorize passthrough: sign in a stand-in user with the requested scopes and the
    // resources those scopes resolve to. The tenant URN scope carries the tenant URN as a
    // resource, so it lands in the token's aud (the native binding, no custom field).
    private static async Task<IResult> IssueAuthorizationCodeAsync(
        HttpContext context,
        IOpenIddictScopeManager scopeManager)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict request could not be retrieved.");

        var identity = new ClaimsIdentity(ServerScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, "test-user");

        var scopes = request.GetScopes();
        identity.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(scopes))
        {
            resources.Add(resource);
        }

        identity.SetResources(resources);
        identity.SetDestinations(static _ => [Destinations.AccessToken]);

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, ServerScheme);
    }

    // Token passthrough: recover the principal the engine validated for the code/refresh
    // grant and re-issue. The audience handler and resource validation have already run.
    private static async Task ExchangeTokenAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict request could not be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
        {
            await context.ForbidAsync(ServerScheme);
            return;
        }

        var result = await context.AuthenticateAsync(ServerScheme);
        await context.SignInAsync(ServerScheme, result.Principal!);
    }

    private async Task SeedAsync()
    {
        using var scope = Services.CreateScope();

        var oidc = scope.ServiceProvider.GetRequiredService<IdmtOpenIddictDbContext>();
        await oidc.Database.EnsureCreatedAsync();
        var tenants = scope.ServiceProvider.GetRequiredService<IdmtTenantStoreDbContext>();
        await tenants.Database.EnsureCreatedAsync();

        // Tenants in the Finbuckle store (resolved per request by X-Tenant).
        foreach (var identifier in new[] { TenantA, TenantB })
        {
            if (!await tenants.TenantInfo.AnyAsync(t => t.Identifier == identifier))
            {
                tenants.TenantInfo.Add(new IdmtTenantInfo(identifier, identifier));
            }
        }

        await tenants.SaveChangesAsync();

        // Task-13 stand-in: each tenant URN registered as a scope whose Resources carry
        // the URN, so requesting the scope binds the URN as the token audience.
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        foreach (var identifier in new[] { TenantA, TenantB })
        {
            var urn = TenantUrns.For(identifier);
            if (await scopes.FindByNameAsync(urn) is null)
            {
                await scopes.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = urn,
                    Resources = { urn },
                });
            }
        }

        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await apps.FindByClientIdAsync(ClientId) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,
                RedirectUris = { new Uri(RedirectUri) },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Prefixes.Scope + TenantUrns.For(TenantA),
                    Permissions.Prefixes.Scope + TenantUrns.For(TenantB),
                },
            });
        }
    }

    private sealed class TokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")]
        public string? AccessToken { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; init; }
    }
}
