using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;

namespace Idmt.Plugin.Services;

internal sealed class CurrentUserService(IMultiTenantContextAccessor multiTenantContextAccessor) : ICurrentUserService
{
    public ClaimsPrincipal? User { get; private set; }

    public string? IpAddress { get; private set; }

    public string? UserAgent { get; private set; }

    public Guid? UserId => 
        Guid.TryParse(User?.FindFirstValue(ClaimTypes.NameIdentifier) ?? Guid.Empty.ToString(), out var userId) ? userId : null;

    public string? UserIdAsString => User?.FindFirstValue(ClaimTypes.NameIdentifier);

    public string? Email => User?.FindFirstValue(ClaimTypes.Email);

    public string? UserName => User?.FindFirstValue(ClaimTypes.Name);

    public string? TenantId => multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id;

    public bool IsInRole(string role)
    {
        return User?.IsInRole(role) ?? false;
    }

    public void SetCurrentUser(ClaimsPrincipal? user, string? ipAddress, string? userAgent)
    {
        User = user;
        IpAddress = ipAddress;
        UserAgent = userAgent;
    }
}
