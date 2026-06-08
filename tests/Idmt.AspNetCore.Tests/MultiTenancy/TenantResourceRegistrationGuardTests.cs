using Idmt.AspNetCore.MultiTenancy;
using Idmt.AspNetCore.Persistence;
using Idmt.AspNetCore.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Idmt.AspNetCore.Tests.MultiTenancy;

/// <summary>
/// Proves the ADR §2.9 startup self-check fails fast if a consumer registers a tenant URN
/// as a static OpenIddict resource, which would defeat the refresh audience precedence rule.
/// </summary>
public sealed class TenantResourceRegistrationGuardTests
{
    [Fact]
    public async Task Startup_Throws_WhenTenantUrnRegisteredAsStaticResource()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var build = async () =>
        {
            using var host = await BuildHostAsync(connection, registerTenantUrnAsResource: true);
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(build);
        Assert.Contains("must not be registered as a static OpenIddict resource", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_Succeeds_WhenNoTenantUrnRegisteredAsResource()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        using var host = await BuildHostAsync(connection, registerTenantUrnAsResource: false);

        // Reaching here means the guard let a clean configuration start.
        Assert.NotNull(host);
    }

    private static Task<IHost> BuildHostAsync(SqliteConnection connection, bool registerTenantUrnAsResource) =>
        new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddDbContext<IdmtOpenIddictDbContext>(o =>
                    {
                        o.UseSqlite(connection);
                        o.UseOpenIddict();
                    });
                    services.AddDbContext<IdmtTenantStoreDbContext>(o => o.UseSqlite(connection));
                    services.AddIdmtMultiTenancy();
                    services.AddIdmtOpenIddictServer(configureServer: o =>
                    {
                        o.AddDevelopmentEncryptionCertificate();
                        o.AddDevelopmentSigningCertificate();
                        o.UseAspNetCore().DisableTransportSecurityRequirement();
                        if (registerTenantUrnAsResource)
                        {
                            o.RegisterResources(TenantUrns.For("acme"));
                        }
                    });
                    services.AddRouting();
                });

                web.Configure(app => app.UseRouting());
            })
            .StartAsync();
}
