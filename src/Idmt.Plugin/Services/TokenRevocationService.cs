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
            existing.RevokedAt = now;
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

        await dbContext.SaveChangesAsync(cancellationToken);
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
