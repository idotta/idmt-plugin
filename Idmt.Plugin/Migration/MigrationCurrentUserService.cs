using System.Security.Claims;
using Idmt.Plugin.Services;

namespace Idmt.Plugin.Migration;

/// <summary>
/// <see cref="ICurrentUserService"/> stub used during the canonical identity data
/// migration. The migration runs in an offline harness without an HTTP context and
/// without an authenticated principal; this implementation lets <see cref="Persistence.IdmtDbContext"/>
/// emit audit rows during <c>SaveChangesAsync</c> without throwing a NRE.
/// </summary>
/// <remarks>
/// All identity-bearing properties return <see langword="null"/> / <see langword="false"/>.
/// Audit rows written under this service therefore carry a <c>UserId = null</c>, which is
/// the intended sentinel for system-driven mutations during migration.
/// </remarks>
internal sealed class MigrationCurrentUserService : ICurrentUserService
{
    public ClaimsPrincipal? User => null;

    public string? IpAddress => null;

    public string? UserAgent => null;

    public Guid? UserId => null;

    public string? UserIdAsString => null;

    public string? Email => null;

    public string? UserName => null;

    public string? TenantId => null;

    public string? TenantIdentifier => null;

    public bool IsActive => false;

    public bool IsInRole(string role) => false;

    void ICurrentUserService.SetCurrentUser(ClaimsPrincipal? user, string? ipAddress, string? userAgent)
    {
        // No-op: migration harness has no caller principal to track.
    }
}
