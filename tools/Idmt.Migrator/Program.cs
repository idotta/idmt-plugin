using Idmt.Plugin.Extensions;
using Idmt.Plugin.Migration;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Idmt.Migrator;

/// <summary>
/// CLI host for <see cref="CanonicalIdentityDataMigrator"/>. Documented harness — not a
/// hardened production tool. Wires the migrator against a consumer-supplied
/// <c>appsettings.json</c> + environment variables.
/// </summary>
internal static class Program
{
    private const string DryRunSwitch = "--dry-run";
    private const string ApplySwitch = "--apply";
    private const string AckSwitch = "--ack-dryrun-fingerprint";
    private const string AcceptCrossTenantSwitch = "--accept-cross-tenant-merges";
    private const string ProviderSwitch = "--provider";

    public static async Task<int> Main(string[] args)
    {
        var parsed = ParseArgs(args);
        if (parsed is null)
        {
            PrintUsage();
            return 1;
        }

        using var host = BuildHost(parsed.Provider);
        var migrator = host.Services.GetRequiredService<CanonicalIdentityDataMigrator>();
        var logger = host.Services.GetRequiredService<ILogger<MigratorMarker>>();

        try
        {
            if (parsed.IsDryRun)
            {
                var report = await migrator.DryRunAsync();
                Console.WriteLine($"fingerprint={report.Fingerprint}");
                Console.WriteLine($"totalUsers={report.TotalUsers}");
                Console.WriteLine($"duplicateGroups={report.DuplicateGroups.Count}");
                foreach (var group in report.DuplicateGroups)
                {
                    Console.WriteLine($"  group email={group.NormalizedEmail} canonical={group.CanonicalUserId} duplicates={group.DuplicateUserIds.Length} sysRole={group.FoldedSysRole}");
                }
                return 0;
            }

            if (parsed.IsApply)
            {
                if (string.IsNullOrEmpty(parsed.AckFingerprint))
                {
                    Console.Error.WriteLine($"missing {AckSwitch}; refusing to apply.");
                    return 2;
                }

                var report = await migrator.ApplyAsync(parsed.AckFingerprint, parsed.AcceptedCrossTenantGroupIds);
                Console.WriteLine($"groupsProcessed={report.GroupsProcessed}");
                Console.WriteLine($"tenantAccessRewrites={report.Rewrites.TenantAccess}");
                Console.WriteLine($"auditRewrites={report.Rewrites.AuditLogs}");
                Console.WriteLine($"identityUserRoleRewrites={report.Rewrites.IdentityUserRoles}");
                Console.WriteLine($"identityUserTokenRewrites={report.Rewrites.IdentityUserTokens}");
                Console.WriteLine($"legacyRevocationsDeleted={report.Rewrites.LegacyRevocationsDeleted}");
                Console.WriteLine($"duplicatesDeleted={report.Rewrites.DuplicatesDeleted}");
                Console.WriteLine($"securityStampsRotated={report.StampsRotated}");
                return 0;
            }

            PrintUsage();
            return 1;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Migration failed");
            Console.Error.WriteLine($"error: {ex.Message}");
            return 3;
        }
    }

    private static IHost BuildHost(DatabaseProvider provider)
    {
        var builder = Host.CreateApplicationBuilder();

        builder.Configuration
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables(prefix: "IDMT_");

        // Override the default ICurrentUserService BEFORE AddIdmt registers the live one, by
        // post-processing the resulting service collection.
        builder.Services.AddIdmt<IdmtDbContext>(
            builder.Configuration,
            configureDb: options =>
            {
                var connectionString = builder.Configuration.GetConnectionString("Idmt")
                    ?? throw new InvalidOperationException("ConnectionStrings:Idmt is not configured.");
                switch (provider)
                {
                    case DatabaseProvider.Sqlite:
                        options.UseSqlite(connectionString);
                        break;
                    case DatabaseProvider.SqlServer:
                        options.UseSqlServer(connectionString);
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported provider: {provider}");
                }
            });

        // Replace the scoped ICurrentUserService with the migration stub and register the
        // migrator. The live ICurrentUserService expects an HTTP context; we have none.
        builder.Services.AddIdmtMigration();

        return builder.Build();
    }

    private static ParsedArgs? ParseArgs(string[] args)
    {
        if (args.Length == 0)
        {
            return null;
        }

        var parsed = new ParsedArgs();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case DryRunSwitch:
                    parsed.IsDryRun = true;
                    break;
                case ApplySwitch:
                    parsed.IsApply = true;
                    break;
                case AckSwitch when i + 1 < args.Length:
                    parsed.AckFingerprint = args[++i];
                    break;
                // Explicit "missing value" guard arms. Without these, a value-taking switch
                // appearing as the trailing argument would fall through to the default
                // "unknown argument" branch, which is misleading UX (the switch is known;
                // its value is simply absent).
                case AckSwitch:
                    Console.Error.WriteLine($"missing value for {AckSwitch}");
                    return null;
                case AcceptCrossTenantSwitch when i + 1 < args.Length:
                    parsed.AcceptedCrossTenantGroupIds = args[++i]
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    break;
                case AcceptCrossTenantSwitch:
                    Console.Error.WriteLine($"missing value for {AcceptCrossTenantSwitch}");
                    return null;
                case ProviderSwitch when i + 1 < args.Length:
                    if (!Enum.TryParse<DatabaseProvider>(args[++i], ignoreCase: true, out var prov))
                    {
                        Console.Error.WriteLine($"invalid provider; expected one of: {string.Join(", ", Enum.GetNames<DatabaseProvider>())}");
                        return null;
                    }
                    parsed.Provider = prov;
                    break;
                case ProviderSwitch:
                    Console.Error.WriteLine($"missing value for {ProviderSwitch}");
                    return null;
                default:
                    Console.Error.WriteLine($"unknown argument: {arg}");
                    return null;
            }
        }

        if (parsed.IsDryRun == parsed.IsApply)
        {
            // either both true or both false → invalid.
            Console.Error.WriteLine($"specify exactly one of {DryRunSwitch} | {ApplySwitch}.");
            return null;
        }

        return parsed;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine($"""
Idmt.Migrator — canonical identity data migration tool (documented harness).

Usage:
  Idmt.Migrator {DryRunSwitch} [{ProviderSwitch} sqlite|sqlserver]
  Idmt.Migrator {ApplySwitch} {AckSwitch} <sha256> [{AcceptCrossTenantSwitch} <id1,id2>] [{ProviderSwitch} sqlite|sqlserver]

Configuration:
  ConnectionStrings:Idmt — required. Provide via appsettings.json or IDMT_ connection-string env var.
""");
    }

    private enum DatabaseProvider
    {
        SqlServer,
        Sqlite,
    }

    private sealed class ParsedArgs
    {
        public bool IsDryRun { get; set; }
        public bool IsApply { get; set; }
        public string? AckFingerprint { get; set; }
        public string[] AcceptedCrossTenantGroupIds { get; set; } = [];
        public DatabaseProvider Provider { get; set; } = DatabaseProvider.SqlServer;
    }

    private sealed class MigratorMarker
    {
    }
}
