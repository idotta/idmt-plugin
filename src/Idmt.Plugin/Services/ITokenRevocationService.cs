namespace Idmt.Plugin.Services;

public interface ITokenRevocationService
{
    Task RevokeUserTokensAsync(Guid userId, string tenantId, CancellationToken cancellationToken = default);
    Task<bool> IsTokenRevokedAsync(Guid userId, string tenantId, DateTime issuedAt, CancellationToken cancellationToken = default);
    Task CleanupExpiredAsync(CancellationToken cancellationToken = default);
}
