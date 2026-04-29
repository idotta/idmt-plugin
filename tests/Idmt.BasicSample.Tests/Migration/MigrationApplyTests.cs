using System.Net;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Migration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.BasicSample.Tests.Migration;

/// <summary>
/// Step 11 / F42 integration tests for the canonical identity data migrator.
/// </summary>
/// <remarks>
/// <b>Residual deferrals (Step 11 plan §C / §D):</b>
/// <list type="bullet">
///   <item><description><b>F41</b> (<c>Migration_StartsFromPhase0SchemaSnapshot</c>) — deferred.
///   Plan called for a hand-written Phase 0 DDL snapshot (<c>Phase0SchemaSnapshot.sql</c>) to be
///   loaded into a SQLite fixture and validated by SHA-256. Deferred because the codebase has
///   already shipped Phase 1 model changes; regenerating the legacy DDL from commit
///   <c>59d31f0</c> requires more migration tooling than the harness warrants. Consumers
///   verify migration output against their own pre-migration schema; the plugin ships the
///   migration code, the snapshot artifact is consumer-side.</description></item>
///   <item><description><b>F47</b> (<c>Migration_AuditEmission_ExactCount</c>) — deferred.
///   Auditing during migration is exercised indirectly via the migrator unit tests (audit
///   rewrite happy path). Pinning an exact count requires fixturing the legacy seed shape
///   that F41 would produce; without F41 it is brittle.</description></item>
/// </list>
/// <b>Honest scope here:</b> F42 exercises the load-bearing security invariant — that running
/// the migrator's <c>SecurityStamp</c> rotation invalidates any bearer / refresh ticket minted
/// before migration. The test does NOT load Phase 0 DDL; it boots the live test factory
/// (Phase 1 schema), mints tokens via <c>/auth/token</c>, runs <c>ApplyAsync</c> against a
/// sibling DI container sharing the same SQLite connection, then asserts the pre-migration
/// refresh token is rejected at <c>/auth/refresh</c>.
/// </remarks>
public sealed class MigrationApplyTests : BaseIntegrationTest
{
    public MigrationApplyTests(IdmtApiFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Migration_PreMigrationBearerToken_RejectedAfterStampRotation()
    {
        // Arrange: mint a bearer + refresh token via the live login flow.
        var client = Factory.CreateClientWithTenant();
        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword,
        });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(tokens);

        // Sanity: refresh works before migration runs.
        var preRefresh = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(tokens!.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, preRefresh.StatusCode);
        var refreshedTokens = await preRefresh.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(refreshedTokens);

        // Act: run the migrator against a sibling DI container that shares the same SQLite
        // connection as the running test host. With no duplicates seeded the dry-run reports
        // zero groups but ApplyAsync still rotates SecurityStamp on every surviving user —
        // that rotation is the security invariant under test.
        await RunMigrationAsync();

        // Assert: the previously-refreshed bearer/refresh ticket is now invalid because its
        // SecurityStamp claim no longer matches the user's row.
        var postRefresh = await client.PostAsJsonAsync(
            "/auth/refresh",
            new RefreshToken.RefreshTokenRequest(refreshedTokens!.RefreshToken));

        Assert.Equal(HttpStatusCode.Unauthorized, postRefresh.StatusCode);
    }

    private async Task RunMigrationAsync()
    {
        var connection = Factory.SharedConnection
            ?? throw new InvalidOperationException("Test factory is not initialised; SharedConnection unavailable.");

        // Build a sibling DI container scoped to the migrator. Sharing the same SQLite
        // connection means writes here are visible to the live host's IdmtDbContext on the
        // next read.
        var services = new ServiceCollection();

        var tenantAccessor = new Mock<IMultiTenantContextAccessor>();
        var sentinelTenant = new IdmtTenantInfo(
            id: IdmtApiFactory.DefaultTenantIdentifier,
            identifier: IdmtApiFactory.DefaultTenantIdentifier,
            name: "Migration Sentinel");
        tenantAccessor.SetupGet(x => x.MultiTenantContext)
            .Returns(new MultiTenantContext<IdmtTenantInfo>(sentinelTenant));

        services.AddSingleton(tenantAccessor.Object);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(NullLoggerFactory.Instance);
        services.AddLogging();
        services.AddDbContext<IdmtDbContext>(options => options.UseSqlite(connection));
        services.AddIdmtMigration();

        await using var sp = services.BuildServiceProvider();

        var migrator = sp.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dryRun = await migrator.DryRunAsync();
        await migrator.ApplyAsync(dryRun.Fingerprint, []);
    }
}
