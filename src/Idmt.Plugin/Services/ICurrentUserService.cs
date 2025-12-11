using System.Security.Claims;

namespace Idmt.Plugin.Services;

public interface ICurrentUserService
{
    ClaimsPrincipal? User { get; }
    string? IpAddress { get; }
    string? UserAgent { get; }
    
    Guid? UserId { get; }
    string? UserIdAsString { get; }
    string? Email { get; }
    string? UserName { get; }
    string? TenantId { get; }

    bool IsInRole(string role);

    internal void SetCurrentUser(ClaimsPrincipal? user, string? ipAddress, string? userAgent);
}
