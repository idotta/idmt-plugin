using System.Security.Claims;
using Microsoft.AspNetCore; // OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerRequest
using Idmt.AspNetCore.Persistence;
using Idmt.AspNetCore.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.AspNetCore.Tests.Server;

/// <summary>
/// A minimal in-process host that exercises <see cref="OpenIddictServerServiceCollectionExtensions.AddIdmtOpenIddictServer"/>
/// against the real OpenIddict handlers. It registers only the OpenIddict context
/// (gate 1 needs nothing else), seeds one confidential client, and maps a stand-in
/// token handler plus a protected resource endpoint.
///
/// The stand-in <c>/connect/token</c> handler stands in for the gated handler task 06
/// will own: it issues a client-credentials principal with no tenant/audience, which
/// is all gate 1 (instant revocation) requires.
/// </summary>
public sealed class OpenIddictServerTestHost : IAsyncLifetime
{
    public const string ClientId = "test-client";
    public const string ClientSecret = "test-secret";

    private SqliteConnection _connection = null!;
    private IHost _host = null!;

    public IServiceProvider Services => _host.Services;

    public HttpClient CreateClient() => _host.GetTestClient();

    public async Task InitializeAsync()
    {
        // Kept open for the host lifetime so the :memory: database survives.
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        _host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddDbContext<IdmtOpenIddictDbContext>(o =>
                    {
                        o.UseSqlite(_connection);
                        o.UseOpenIddict();
                    });

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
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapPost("/connect/token", IssueClientCredentialsTokenAsync);
                        endpoints.MapGet("/whoami", () => Results.Ok("ok")).RequireAuthorization();
                    });
                });
            })
            .StartAsync();

        await SeedClientAsync();
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }

        _connection?.Dispose();
    }

    // Stand-in for the task-06 gated handler: mint a client-credentials principal.
    private static async Task IssueClientCredentialsTokenAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict request could not be retrieved.");

        if (!request.IsClientCredentialsGrantType())
        {
            await context.ForbidAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return;
        }

        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        identity.SetClaim(Claims.Subject, request.ClientId);
        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(static _ => [Destinations.AccessToken]);

        await context.SignInAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }

    private async Task SeedClientAsync()
    {
        using var scope = Services.CreateScope();

        var db = scope.ServiceProvider.GetRequiredService<IdmtOpenIddictDbContext>();
        await db.Database.EnsureCreatedAsync();

        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await apps.FindByClientIdAsync(ClientId) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + IdmtScopes.Api,
                },
            });
        }
    }
}
