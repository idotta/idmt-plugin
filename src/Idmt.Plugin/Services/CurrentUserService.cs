using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

internal sealed class CurrentUserService(
    IOptions<IdmtOptions> idmtOptions,
    IMultiTenantContextAccessor multiTenantContextAccessor) : ICurrentUserService
{
    public ClaimsPrincipal? User { get; private set; }

    public string? IpAddress { get; private set; }

    public string? UserAgent { get; private set; }

    public Guid? UserId =>
        Guid.TryParse(User?.FindFirstValue(ClaimTypes.NameIdentifier) ?? Guid.Empty.ToString(), out var userId) ? userId : null;

    public string? UserIdAsString => User?.FindFirstValue(ClaimTypes.NameIdentifier);

    public string? Email => User?.FindFirstValue(ClaimTypes.Email);

    public string? UserName => User?.FindFirstValue(ClaimTypes.Name);

    public string? TenantId =>
        multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id;

    public string? TenantIdentifier =>
        User?.FindFirstValue(idmtOptions.Value.MultiTenant.StrategyOptions.GetValueOrDefault(IdmtMultiTenantStrategy.Claim, IdmtMultiTenantStrategy.DefaultClaim)) ??
        multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier;

    public bool IsActive => string.Equals(User?.FindFirstValue("is_active"), "true", StringComparison.OrdinalIgnoreCase);

    public bool IsInRole(string role) => User?.IsInRole(role) ?? false;

    public void SetCurrentUser(ClaimsPrincipal? user, string? ipAddress, string? userAgent)
    {
        User = user;
        IpAddress = ipAddress;
        UserAgent = userAgent;
    }
}
