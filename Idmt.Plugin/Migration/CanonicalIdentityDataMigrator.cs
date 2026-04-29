using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Migration;

/// <summary>
/// Phase 1 canonical identity data migrator.
/// </summary>
/// <remarks>
/// <para>
/// This is a <b>documented harness</b>, not a production-grade migration tool. It implements
/// the data rewrites described in <c>SECURITY_PHASE_1_CANONICAL_IDENTITY.md §"Migration for
/// existing deployments"</c>:
/// </para>
/// <list type="number">
///   <item><description>Group existing <see cref="IdmtUser"/> rows by <c>NormalizedEmail</c>;
///   pick canonical <c>Id</c> (oldest row).</description></item>
///   <item><description>Rewrite <see cref="TenantAccess.UserId"/>, <c>IdentityUserRole.UserId</c>,
///   <see cref="RevokedToken"/>, <c>AspNetUserTokens.UserId</c>, <see cref="IdmtAuditLog.UserId"/>
///   for <see cref="IdmtUser"/> mutations to the canonical id.</description></item>
///   <item><description>Fold <see cref="SysRoleKind"/> across duplicates (highest authority wins).</description></item>
///   <item><description>Drop duplicate <see cref="IdmtUser"/> rows.</description></item>
///   <item><description>Rotate <see cref="IdmtUser.SecurityStamp"/> on every survivor so any
///   bearer / refresh ticket minted before the migration is invalidated at first refresh.</description></item>
/// </list>
/// <para>
/// Consumers verify the migration output against their own pre-migration schema. The plugin
/// ships the migration code; the schema snapshot itself is a consumer-side concern.
/// </para>
/// </remarks>
public sealed class CanonicalIdentityDataMigrator
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CanonicalIdentityDataMigrator> _logger;

    /// <summary>
    /// Synthetic tenant identifier injected into the DI scope while migration runs so that
    /// any code path that resolves a <see cref="IMultiTenantContextAccessor"/> finds a
    /// non-null context. Migration itself is global.
    /// </summary>
    public const string MigrationTenantIdentifier = "__migration__";

    public CanonicalIdentityDataMigrator(
        IServiceProvider serviceProvider,
        ILogger<CanonicalIdentityDataMigrator> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Inspect the existing identity data, group <see cref="IdmtUser"/> rows by
    /// <c>NormalizedEmail</c>, and emit a divergence report. Does not mutate state.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The dry-run report. <see cref="DryRunReport.Fingerprint"/> must be supplied
    /// to <see cref="ApplyAsync"/> as proof-of-review.</returns>
    public async Task<DryRunReport> DryRunAsync(CancellationToken ct = default)
    {
        await using var scope = CreateMigrationScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdmtDbContext>();

        // Pull all users; we group in memory so dedup logic is identical in dry-run + apply.
        var users = await dbContext.Users
            .AsNoTracking()
            .ToListAsync(ct);

        var groups = users
            .Where(u => !string.IsNullOrEmpty(u.NormalizedEmail))
            .GroupBy(u => u.NormalizedEmail!, StringComparer.Ordinal)
            .ToList();

        var duplicateGroups = groups
            .Where(g => g.Count() > 1)
            .Select(g => new DuplicateGroup(
                NormalizedEmail: g.Key,
                CanonicalUserId: PickCanonicalId(g),
                DuplicateUserIds: g.Select(u => u.Id).Where(id => id != PickCanonicalId(g)).ToArray(),
                FoldedSysRole: FoldSysRole(g)))
            .OrderBy(g => g.NormalizedEmail, StringComparer.Ordinal)
            .ToList();

        var totalDuplicates = duplicateGroups.Sum(g => g.DuplicateUserIds.Length);

        var fingerprint = ComputeFingerprint(duplicateGroups);

        _logger.LogInformation(
            "Dry-run complete. TotalUsers={TotalUsers} DuplicateGroups={DuplicateGroups} TotalDuplicateRows={TotalDuplicates} Fingerprint={Fingerprint}",
            users.Count, duplicateGroups.Count, totalDuplicates, fingerprint);

        return new DryRunReport(
            TotalUsers: users.Count,
            DuplicateGroups: duplicateGroups,
            Fingerprint: fingerprint);
    }

    /// <summary>
    /// Apply the canonical identity migration. Refuses to run unless <paramref name="ackFingerprint"/>
    /// matches the current dry-run fingerprint.
    /// </summary>
    /// <param name="ackFingerprint">SHA-256 fingerprint returned by an immediately-prior call to
    /// <see cref="DryRunAsync"/>. Required to ensure operator reviewed divergence before applying.</param>
    /// <param name="acceptedCrossTenantMergeGroupIds">Reserved for future use. Pass an empty
    /// enumerable. Cross-tenant duplicate groups are accepted unconditionally in this revision.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Apply summary.</returns>
    public async Task<ApplyReport> ApplyAsync(
        string ackFingerprint,
        IEnumerable<string> acceptedCrossTenantMergeGroupIds,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(ackFingerprint);
        ArgumentNullException.ThrowIfNull(acceptedCrossTenantMergeGroupIds);

        var dryRun = await DryRunAsync(ct);
        if (!string.Equals(dryRun.Fingerprint, ackFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Dry-run fingerprint mismatch. Re-run --dry-run and pass the new fingerprint. expected={dryRun.Fingerprint} got={ackFingerprint}");
        }

        await using var scope = CreateMigrationScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdmtDbContext>();

        // Suspend Finbuckle's tenant-mismatch check so we can write across all tenant rows
        // (audit logs, IdentityUserRole, TenantAccess, ...) inside a single transaction.
        var previousMode = dbContext.TenantMismatchMode;
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;

        var rewriteCounts = new RewriteCounts();
        try
        {
            // Wrap all mutations in an explicit transaction. ApplyGroupAsync mixes
            // change-tracker writes (TenantAccess, AuditLogs, SysRole fold) with bulk
            // operations (ExecuteUpdateAsync / ExecuteDeleteAsync against UserRoles,
            // UserTokens, RevokedTokens, Users). Bulk operations auto-commit immediately
            // and bypass the change tracker, so without an explicit transaction a failure
            // in the trailing SaveChangesAsync (or anywhere mid-loop) would leave the DB
            // partially migrated with no rollback path. The transaction guarantees
            // all-or-nothing semantics across both write modes.
            await using var transaction = await dbContext.Database.BeginTransactionAsync(ct);
            try
            {
                foreach (var group in dryRun.DuplicateGroups)
                {
                    rewriteCounts = await ApplyGroupAsync(dbContext, group, rewriteCounts, ct);
                }

                // Rotate SecurityStamp on EVERY surviving user (canonical and unaffected). Any
                // bearer / refresh ticket minted before the migration relies on the prior stamp;
                // rotation forces all such tickets to fail at first refresh. F42 invariant.
                var stampRotated = await RotateAllSecurityStampsAsync(dbContext, ct);

                await dbContext.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);

                _logger.LogInformation(
                    "Migration applied. Groups={Groups} TenantAccessRewrites={TA} AuditRewrites={Audit} RoleRewrites={Roles} TokenRewrites={UT} StampRotations={Stamps} DuplicatesDeleted={Deletes}",
                    dryRun.DuplicateGroups.Count, rewriteCounts.TenantAccess, rewriteCounts.AuditLogs,
                    rewriteCounts.IdentityUserRoles, rewriteCounts.IdentityUserTokens, stampRotated, rewriteCounts.DuplicatesDeleted);

                return new ApplyReport(
                    GroupsProcessed: dryRun.DuplicateGroups.Count,
                    Rewrites: rewriteCounts,
                    StampsRotated: stampRotated);
            }
            catch
            {
                await transaction.RollbackAsync(ct);
                throw;
            }
        }
        finally
        {
            dbContext.TenantMismatchMode = previousMode;
        }
    }

    private async Task<RewriteCounts> ApplyGroupAsync(
        IdmtDbContext dbContext,
        DuplicateGroup group,
        RewriteCounts counts,
        CancellationToken ct)
    {
        var canonicalId = group.CanonicalUserId;
        var duplicates = group.DuplicateUserIds;

        // Step 1: rewrite TenantAccess rows that point at any duplicate.
        var taRows = await dbContext.TenantAccess
            .Where(ta => duplicates.Contains(ta.UserId))
            .ToListAsync(ct);
        foreach (var row in taRows)
        {
            row.UserId = canonicalId;
        }
        counts = counts with { TenantAccess = counts.TenantAccess + taRows.Count };

        // Step 2: rewrite IdmtAuditLog rows.
        var auditRows = await dbContext.AuditLogs
            .Where(a => a.UserId.HasValue && duplicates.Contains(a.UserId.Value))
            .ToListAsync(ct);
        foreach (var row in auditRows)
        {
            row.UserId = canonicalId;
        }
        counts = counts with { AuditLogs = counts.AuditLogs + auditRows.Count };

        // Step 3: rewrite IdentityUserRole rows. Use raw connection because the navigation
        // property graph of MultiTenantIdentityDbContext makes EF tracking awkward across
        // composite-key entities. ExecuteUpdate keeps it provider-agnostic.
        var userRoleRewrites = 0;
        foreach (var dup in duplicates)
        {
            var dupCopy = dup;
            var canonicalCopy = canonicalId;
            userRoleRewrites += await dbContext.UserRoles
                .Where(ur => ur.UserId == dupCopy)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.UserId, _ => canonicalCopy), ct);
        }
        counts = counts with { IdentityUserRoles = counts.IdentityUserRoles + userRoleRewrites };

        // Step 4: rewrite IdentityUserToken rows.
        var userTokenRewrites = 0;
        foreach (var dup in duplicates)
        {
            var dupCopy = dup;
            var canonicalCopy = canonicalId;
            userTokenRewrites += await dbContext.UserTokens
                .Where(ut => ut.UserId == dupCopy)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.UserId, _ => canonicalCopy), ct);
        }
        counts = counts with { IdentityUserTokens = counts.IdentityUserTokens + userTokenRewrites };

        // Note: RevokedToken keys are composite "{userId}:{tenantId}" strings (see
        // TokenRevocationService.BuildTokenId). Rewriting them risks collisions with existing
        // canonical-keyed rows. Migration drops legacy duplicate-keyed revocations; consumers
        // must accept that pre-migration revocations on shadow-row userIds will lose their
        // record. In practice the SecurityStamp rotation (Step 6) invalidates all pre-migration
        // refresh tickets anyway, which is the security-critical invariant.
        var legacyRevocationDeletes = 0;
        foreach (var dup in duplicates)
        {
            var prefix = $"{dup}:";
            var prefixCopy = prefix;
            legacyRevocationDeletes += await dbContext.RevokedTokens
                .Where(rt => rt.TokenId.StartsWith(prefixCopy))
                .ExecuteDeleteAsync(ct);
        }
        counts = counts with { LegacyRevocationsDeleted = counts.LegacyRevocationsDeleted + legacyRevocationDeletes };

        // Step 5: fold SysRole onto canonical row.
        var canonical = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == canonicalId, ct);
        if (canonical is not null)
        {
            if ((int)canonical.SysRole < (int)group.FoldedSysRole)
            {
                canonical.SysRole = group.FoldedSysRole;
            }
        }

        // Step 6: drop duplicate IdmtUser rows.
        var deleted = await dbContext.Users
            .Where(u => duplicates.Contains(u.Id))
            .ExecuteDeleteAsync(ct);
        counts = counts with { DuplicatesDeleted = counts.DuplicatesDeleted + deleted };

        return counts;
    }

    private static async Task<int> RotateAllSecurityStampsAsync(IdmtDbContext dbContext, CancellationToken ct)
    {
        // Generate a deterministic-looking but unique-per-row stamp. Identity treats SecurityStamp
        // opaquely, so any change invalidates downstream tickets validated via
        // SignInManager.ValidateSecurityStampAsync.
        var users = await dbContext.Users.ToListAsync(ct);
        foreach (var user in users)
        {
            user.SecurityStamp = Guid.NewGuid().ToString("N");
        }
        return users.Count;
    }

    private static Guid PickCanonicalId(IEnumerable<IdmtUser> group)
    {
        // Guid.CreateVersion7 (used by IdmtUser) is monotonic by creation time, so the
        // smallest value is the oldest row. Falls back to Guid.CompareTo for non-v7 ids.
        return group.Min(u => u.Id);
    }

    private static SysRoleKind FoldSysRole(IEnumerable<IdmtUser> group)
    {
        // Highest authority wins. SysAdmin > SysSupport > None.
        var max = group.Max(u => (int)u.SysRole);
        return (SysRoleKind)max;
    }

    private static string ComputeFingerprint(IReadOnlyList<DuplicateGroup> groups)
    {
        // Stable, deterministic hash of the dry-run output so the operator must re-acknowledge
        // if the data drifts between dry-run and apply.
        var sb = new StringBuilder();
        foreach (var group in groups.OrderBy(g => g.NormalizedEmail, StringComparer.Ordinal))
        {
            sb.Append(group.NormalizedEmail).Append('|');
            sb.Append(group.CanonicalUserId.ToString("N", CultureInfo.InvariantCulture)).Append('|');
            sb.Append(((int)group.FoldedSysRole).ToString(CultureInfo.InvariantCulture)).Append('|');
            foreach (var dup in group.DuplicateUserIds.OrderBy(g => g))
            {
                sb.Append(dup.ToString("N", CultureInfo.InvariantCulture)).Append(',');
            }
            sb.Append(';');
        }
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()), hash);
        return Convert.ToHexStringLower(hash);
    }

    private AsyncServiceScope CreateMigrationScope()
    {
        var scope = _serviceProvider.CreateAsyncScope();
        // Inject a synthetic multi-tenant context. Some downstream services (e.g. EF query
        // filter providers) read the context during DbContext construction.
        var setter = scope.ServiceProvider.GetService<IMultiTenantContextSetter>();
        if (setter is not null)
        {
            var sentinel = new IdmtTenantInfo(
                id: MigrationTenantIdentifier,
                identifier: MigrationTenantIdentifier,
                name: "Migration Sentinel");
            setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(sentinel);
        }
        return scope;
    }

    /// <summary>
    /// Result of <see cref="DryRunAsync"/>.
    /// </summary>
    public sealed record DryRunReport(
        int TotalUsers,
        IReadOnlyList<DuplicateGroup> DuplicateGroups,
        string Fingerprint);

    /// <summary>
    /// Per-group divergence record.
    /// </summary>
    public sealed record DuplicateGroup(
        string NormalizedEmail,
        Guid CanonicalUserId,
        Guid[] DuplicateUserIds,
        SysRoleKind FoldedSysRole);

    /// <summary>
    /// Result of <see cref="ApplyAsync"/>.
    /// </summary>
    public sealed record ApplyReport(
        int GroupsProcessed,
        RewriteCounts Rewrites,
        int StampsRotated);

    /// <summary>
    /// Counts of rows mutated during apply.
    /// </summary>
    public sealed record RewriteCounts(
        int TenantAccess = 0,
        int AuditLogs = 0,
        int IdentityUserRoles = 0,
        int IdentityUserTokens = 0,
        int LegacyRevocationsDeleted = 0,
        int DuplicatesDeleted = 0);
}
