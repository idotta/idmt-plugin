using Idmt.Spike.Host.Auth;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.Spike.Host.Server;

/// <summary>
/// Gate 2: mints a support token for a system user impersonating a tenant, and
/// writes the audit row in the SAME transaction as the OpenIddict token-store
/// insert. The TenantAccess gate re-runs first.
///
/// Both writes go through one <see cref="IdmtOpenIddictDbContext"/> inside one
/// explicit transaction: the OpenIddict EF store resolves that same scoped
/// context, so its insert and the audit insert commit or roll back together.
/// This is the empirical answer to the ADR's flagged "unproven part" (uncertainty
/// #3): atomicity is achieved by minting through the token manager inside a
/// transaction we own — NOT through the deferred SignIn passthrough, whose token
/// creation runs after the request delegate returns, outside any handler-scoped
/// transaction.
/// </summary>
public sealed class SupportTokenService(
    IOpenIddictTokenManager tokens,
    IdmtOpenIddictDbContext oidb,
    IdmtIdentityDbContext identity,
    ITenantAccessGate gate,
    TimeProvider clock)
{
    public sealed record Result(bool Allowed, string? TokenId, string? Denied);

    /// <summary>
    /// Issues a support token. <paramref name="failAudit"/> injects an audit-write
    /// failure to prove the token does not survive a failed audit.
    /// </summary>
    public async Task<Result> IssueAsync(
        Guid actorUserId,
        string targetTenant,
        string reason,
        bool failAudit,
        CancellationToken ct)
    {
        var actor = await identity.Users.FirstOrDefaultAsync(u => u.Id == actorUserId, ct);
        if (actor is null || actor.SysRole == SysRoleKind.None)
        {
            return new Result(false, null, "not_a_system_user");
        }

        // Uniform TenantAccess gate re-runs at issuance for the exchange grant.
        if (!await gate.CanAccessAsync(actorUserId, targetTenant, ct))
        {
            return new Result(false, null, "no_tenant_access");
        }

        var now = clock.GetUtcNow();
        await using var tx = await oidb.Database.BeginTransactionAsync(ct);

        var descriptor = new OpenIddictTokenDescriptor
        {
            Subject = actorUserId.ToString(),
            Type = "access_token",
            Status = Statuses.Valid,
            CreationDate = now,
            ExpirationDate = now.AddMinutes(15),
            ReferenceId = Guid.NewGuid().ToString("N"),
        };

        // CreateAsync persists the token entry to this same context inside the
        // open transaction (the OpenIddict EF store resolves the same scoped
        // IdmtOpenIddictDbContext instance), so the token is now written but
        // uncommitted.
        var token = await tokens.CreateAsync(descriptor, ct);
        var tokenId = await tokens.GetIdAsync(token, ct);

        // Stage the audit row in the SAME context/transaction. When failAudit is
        // set, Reason is null, which violates the NOT NULL column and makes the
        // audit's SaveChanges fail at the database — AFTER the token was already
        // persisted in this transaction. The transaction never commits, so the
        // already-written token is rolled back: a real audit-write failure drops
        // the token.
        oidb.SupportAudits.Add(new SupportAudit
        {
            ActorUserId = actorUserId,
            TenantId = targetTenant,
            Reason = failAudit ? null! : reason,
            CreatedAt = now,
        });

        await oidb.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        return new Result(true, tokenId, null);
    }
}

internal static class SupportProperties
{
    public const string Tenant = "idmt:support:tenant";
    public const string Actor = "idmt:support:actor";
}
