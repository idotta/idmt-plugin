using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

internal sealed class TokenRevocationService(
    IdmtDbContext dbContext,
    TimeProvider timeProvider,
    IOptions<IdmtOptions> idmtOptions,
    ILogger<TokenRevocationService> logger) : ITokenRevocationService
{
    public async Task RevokeUserTokensAsync(Guid userId, string tenantId, CancellationToken cancellationToken = default)
    {
        var tokenId = BuildTokenId(userId, tenantId);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var expiresAt = now.Add(idmtOptions.Value.Identity.Bearer.RefreshTokenExpiration);

        var existing = await dbContext.RevokedTokens.FindAsync([tokenId], cancellationToken);
        if (existing is not null)
        {
            // Only extend the expiry — never move RevokedAt forward as that
            // would re-validate tokens issued between the old and new timestamps
            existing.ExpiresAt = expiresAt;
        }
        else
        {
            dbContext.RevokedTokens.Add(new RevokedToken
            {
                TokenId = tokenId,
                RevokedAt = now,
                ExpiresAt = expiresAt
            });
        }

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException) when (existing is null)
        {
            // TOCTOU race: a concurrent logout for the same user+tenant won the
            // insert race and triggered a unique constraint violation. Clear the
            // tracker so the conflicting Add is no longer tracked, then reload
            // the winner's record and slide its ExpiresAt forward.
            // RevokedAt is intentionally left untouched — the winning insert
            // already recorded the earliest revocation timestamp, which is
            // correct: moving it forward would re-validate tokens issued between
            // the two concurrent revocation calls.
            dbContext.ChangeTracker.Clear();
            var conflict = await dbContext.RevokedTokens.FindAsync([tokenId], cancellationToken);
            if (conflict is not null)
            {
                conflict.ExpiresAt = expiresAt;
                await dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        logger.LogInformation("Revoked all refresh tokens for user {UserId} in tenant {TenantId}", userId, tenantId);
    }

    public async Task<bool> IsTokenRevokedAsync(Guid userId, string tenantId, DateTime issuedAt, CancellationToken cancellationToken = default)
    {
        var tokenId = BuildTokenId(userId, tenantId);
        var revocation = await dbContext.RevokedTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(rt => rt.TokenId == tokenId, cancellationToken);

        // Strict less-than: a token issued at the exact revocation time is considered new (post-revocation)
        return revocation is not null && issuedAt < revocation.RevokedAt;
    }

    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var count = await dbContext.RevokedTokens
            .Where(rt => rt.ExpiresAt < now)
            .ExecuteDeleteAsync(cancellationToken);

        if (count > 0)
        {
            logger.LogInformation("Cleaned up {Count} expired token revocation records", count);
        }
    }

    private static string BuildTokenId(Guid userId, string tenantId) => $"{userId}:{tenantId}";
}
