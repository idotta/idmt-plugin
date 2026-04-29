using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Migration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Migration;

/// <summary>
/// Unit tests for <see cref="CanonicalIdentityDataMigrator"/>.
/// </summary>
/// <remarks>
/// Coverage scope (per Step 11 plan §A): happy path + null/edge cases. The migrator is a
/// documented harness, not a production-grade tool; full integration coverage of
/// IdentityUserRole / IdentityUserToken rewrites belongs to consumer-side validation.
/// SQLite (in-memory) is used because the migrator relies on <c>ExecuteUpdateAsync</c> which
/// is not supported by the EF InMemory provider.
/// </remarks>
public sealed class CanonicalIdentityDataMigratorTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _serviceProvider;
    private readonly IdmtDbContext _db;

    public CanonicalIdentityDataMigratorTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var services = new ServiceCollection();

        var tenantAccessor = new Mock<IMultiTenantContextAccessor>();
        var dummyTenant = new IdmtTenantInfo("system-test", "system-test", "System Test Tenant");
        tenantAccessor.SetupGet(x => x.MultiTenantContext)
            .Returns(new MultiTenantContext<IdmtTenantInfo>(dummyTenant));

        services.AddSingleton(tenantAccessor.Object);
        services.AddScoped<ICurrentUserService, MigrationCurrentUserService>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(NullLoggerFactory.Instance);
        services.AddLogging();

        services.AddDbContext<IdmtDbContext>(options =>
            options.UseSqlite(_connection));

        services.AddSingleton<CanonicalIdentityDataMigrator>();

        _serviceProvider = services.BuildServiceProvider();
        _db = _serviceProvider.GetRequiredService<IdmtDbContext>();
        _db.Database.EnsureCreated();

        // Drop the Phase-1 NormalizedEmail unique index so the test fixture can simulate
        // pre-migration shadow-row data (multiple IdmtUser rows sharing a NormalizedEmail).
        // Real pre-migration databases have no such global uniqueness constraint.
        DropNormalizedEmailIndex(_connection);
    }

    private static void DropNormalizedEmailIndex(SqliteConnection conn)
    {
        using var lookup = conn.CreateCommand();
        lookup.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='AspNetUsers' AND sql LIKE '%NormalizedEmail%'";
        var indexNames = new List<string>();
        using (var reader = lookup.ExecuteReader())
        {
            while (reader.Read())
            {
                indexNames.Add(reader.GetString(0));
            }
        }
        foreach (var name in indexNames)
        {
            using var drop = conn.CreateCommand();
            drop.CommandText = $"DROP INDEX IF EXISTS \"{name}\"";
            drop.ExecuteNonQuery();
        }
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        _connection.Dispose();
    }

    private (IServiceProvider provider, IdmtDbContext db) BuildHarness() => (_serviceProvider, _db);

    [Fact]
    public async Task DryRun_NoUsers_ReportsZeroGroups()
    {
        var (provider, _) = BuildHarness();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var report = await migrator.DryRunAsync();

        Assert.Equal(0, report.TotalUsers);
        Assert.Empty(report.DuplicateGroups);
        Assert.False(string.IsNullOrEmpty(report.Fingerprint));
    }

    [Fact]
    public async Task DryRun_NoDuplicates_ReportsZeroGroups()
    {
        var (provider, db) = BuildHarness();

        db.Users.Add(NewUser("alice@example.com"));
        db.Users.Add(NewUser("bob@example.com"));
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var report = await migrator.DryRunAsync();

        Assert.Equal(2, report.TotalUsers);
        Assert.Empty(report.DuplicateGroups);
    }

    [Fact]
    public async Task DryRun_DuplicateEmails_GroupsAndPicksOldestAsCanonical()
    {
        var (provider, db) = BuildHarness();

        // GUIDv7 ids are time-ordered; create older first so its id sorts smallest.
        var older = NewUser("dup@example.com");
        await Task.Delay(5);
        var newer = NewUser("dup@example.com");
        db.Users.AddRange(older, newer);
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var report = await migrator.DryRunAsync();

        var group = Assert.Single(report.DuplicateGroups);
        Assert.Equal("DUP@EXAMPLE.COM", group.NormalizedEmail);
        Assert.Equal(older.Id, group.CanonicalUserId);
        Assert.Single(group.DuplicateUserIds);
        Assert.Equal(newer.Id, group.DuplicateUserIds[0]);
    }

    [Fact]
    public async Task DryRun_FoldsHighestSysRoleAcrossDuplicates()
    {
        var (provider, db) = BuildHarness();

        var canonical = NewUser("dup@example.com", SysRoleKind.None);
        await Task.Delay(5);
        var dup = NewUser("dup@example.com", SysRoleKind.SysAdmin);
        db.Users.AddRange(canonical, dup);
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var report = await migrator.DryRunAsync();

        var group = Assert.Single(report.DuplicateGroups);
        Assert.Equal(SysRoleKind.SysAdmin, group.FoldedSysRole);
    }

    [Fact]
    public async Task DryRun_FingerprintIsStableForSameInput()
    {
        var (provider, db) = BuildHarness();

        db.Users.Add(NewUser("a@example.com"));
        db.Users.Add(NewUser("b@example.com"));
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var first = await migrator.DryRunAsync();
        var second = await migrator.DryRunAsync();

        Assert.Equal(first.Fingerprint, second.Fingerprint);
    }

    [Fact]
    public async Task Apply_RefusesWithoutAck()
    {
        var (provider, _) = BuildHarness();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            migrator.ApplyAsync(string.Empty, []));
    }

    [Fact]
    public async Task Apply_RefusesWithStaleFingerprint()
    {
        var (provider, _) = BuildHarness();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            migrator.ApplyAsync("0000000000000000000000000000000000000000000000000000000000000000", []));

        Assert.Contains("fingerprint mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Apply_NoDuplicates_StillRotatesAllSecurityStamps()
    {
        var (provider, db) = BuildHarness();

        var u1 = NewUser("alice@example.com");
        var u2 = NewUser("bob@example.com");
        var stamp1 = u1.SecurityStamp;
        var stamp2 = u2.SecurityStamp;
        db.Users.AddRange(u1, u2);
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dry = await migrator.DryRunAsync();
        var apply = await migrator.ApplyAsync(dry.Fingerprint, []);

        Assert.Equal(0, apply.GroupsProcessed);
        Assert.Equal(2, apply.StampsRotated);

        // Reload from underlying store; in-memory provider tracks stamp mutation directly.
        var reloaded1 = await db.Users.AsNoTracking().FirstAsync(u => u.Id == u1.Id);
        var reloaded2 = await db.Users.AsNoTracking().FirstAsync(u => u.Id == u2.Id);
        Assert.NotEqual(stamp1, reloaded1.SecurityStamp);
        Assert.NotEqual(stamp2, reloaded2.SecurityStamp);
    }

    [Fact]
    public async Task Apply_RewritesTenantAccessAndDropsDuplicates()
    {
        var (provider, db) = BuildHarness();

        var canonical = NewUser("dup@example.com");
        await Task.Delay(5);
        var dup = NewUser("dup@example.com");
        db.Users.AddRange(canonical, dup);

        // TenantAccess pointing at the duplicate id — should be rewritten to canonical id.
        var ta = new TenantAccess
        {
            UserId = dup.Id,
            TenantId = "tenant-x",
            IsActive = true,
        };
        db.TenantAccess.Add(ta);
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dry = await migrator.DryRunAsync();
        var apply = await migrator.ApplyAsync(dry.Fingerprint, []);

        Assert.Equal(1, apply.GroupsProcessed);
        Assert.Equal(1, apply.Rewrites.TenantAccess);
        Assert.Equal(1, apply.Rewrites.DuplicatesDeleted);

        var reloadedTa = await db.TenantAccess.AsNoTracking().FirstAsync(t => t.Id == ta.Id);
        Assert.Equal(canonical.Id, reloadedTa.UserId);

        var remainingUsers = await db.Users.AsNoTracking().ToListAsync();
        Assert.Single(remainingUsers);
        Assert.Equal(canonical.Id, remainingUsers[0].Id);
    }

    [Fact]
    public async Task Apply_FoldsSysRoleHighestWins()
    {
        var (provider, db) = BuildHarness();

        var canonical = NewUser("dup@example.com", SysRoleKind.None);
        await Task.Delay(5);
        var dup = NewUser("dup@example.com", SysRoleKind.SysAdmin);
        db.Users.AddRange(canonical, dup);
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dry = await migrator.DryRunAsync();
        await migrator.ApplyAsync(dry.Fingerprint, []);

        var reloaded = await db.Users.AsNoTracking().FirstAsync(u => u.Id == canonical.Id);
        Assert.Equal(SysRoleKind.SysAdmin, reloaded.SysRole);
    }

    [Fact]
    public async Task Apply_RewritesAuditLogsForDuplicateUserId()
    {
        var (provider, db) = BuildHarness();

        var canonical = NewUser("dup@example.com");
        await Task.Delay(5);
        var dup = NewUser("dup@example.com");
        db.Users.AddRange(canonical, dup);
        await db.SaveChangesAsync();

        // Attribute an audit row to the duplicate user.
        db.AuditLogs.Add(new IdmtAuditLog
        {
            UserId = dup.Id,
            Action = "Test",
            Resource = nameof(IdmtUser),
            Timestamp = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dry = await migrator.DryRunAsync();
        var apply = await migrator.ApplyAsync(dry.Fingerprint, []);

        Assert.True(apply.Rewrites.AuditLogs >= 1);
        var audits = await db.AuditLogs.AsNoTracking().Where(a => a.Resource == "IdmtUser" && a.Action == "Test").ToListAsync();
        Assert.All(audits, a => Assert.Equal(canonical.Id, a.UserId));
    }

    [Fact]
    public async Task Apply_SaveChangesAsyncFails_RollsBackBulkOperations()
    {
        // Verifies the transaction wrap in ApplyAsync. Without a transaction, the bulk
        // ExecuteDeleteAsync against AspNetUsers (Step 6 in ApplyGroupAsync) auto-commits
        // immediately and would leave the database with the duplicate row dropped even
        // if the trailing SaveChangesAsync throws. With BeginTransactionAsync wrapping
        // both modes, all writes roll back together.
        var (provider, db) = BuildHarness();

        var canonical = NewUser("dup@example.com");
        await Task.Delay(5);
        var dup = NewUser("dup@example.com");
        db.Users.AddRange(canonical, dup);

        // Force SaveChangesAsync to fail by pre-creating a unique-index collision: both
        // canonical and duplicate already have a TenantAccess for the same tenant. After
        // the migrator rewrites dupTa.UserId → canonical.Id, the (UserId, TenantId)
        // unique index is violated at SaveChangesAsync time. By that point the bulk
        // ExecuteDeleteAsync against AspNetUsers has already executed; the transaction
        // must roll it back.
        db.TenantAccess.Add(new TenantAccess
        {
            UserId = canonical.Id,
            TenantId = "tenant-x",
            IsActive = true,
        });
        db.TenantAccess.Add(new TenantAccess
        {
            UserId = dup.Id,
            TenantId = "tenant-x",
            IsActive = true,
        });
        await db.SaveChangesAsync();

        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();
        var dry = await migrator.DryRunAsync();

        await Assert.ThrowsAsync<DbUpdateException>(() =>
            migrator.ApplyAsync(dry.Fingerprint, []));

        // Both users must still be present — the bulk delete in ApplyGroupAsync Step 6
        // must have been rolled back along with the failed SaveChangesAsync.
        var remainingUsers = await db.Users.AsNoTracking().ToListAsync();
        Assert.Equal(2, remainingUsers.Count);
        Assert.Contains(remainingUsers, u => u.Id == canonical.Id);
        Assert.Contains(remainingUsers, u => u.Id == dup.Id);
    }

    [Fact]
    public async Task Apply_NullArgumentForCrossTenantList_Throws()
    {
        var (provider, _) = BuildHarness();
        var migrator = provider.GetRequiredService<CanonicalIdentityDataMigrator>();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            migrator.ApplyAsync("ack", null!));
    }

    private static IdmtUser NewUser(string email, SysRoleKind sysRole = SysRoleKind.None) =>
        new()
        {
            Id = Guid.CreateVersion7(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            UserName = email,
            NormalizedUserName = email.ToUpperInvariant(),
            EmailConfirmed = true,
            IsActive = true,
            SysRole = sysRole,
        };
}
