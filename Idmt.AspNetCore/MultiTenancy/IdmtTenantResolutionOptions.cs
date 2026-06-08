namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// Configures how a request is mapped to a tenant. Defaults to the two strategies the
/// spike proved (header then route), so the common case needs no configuration. This is
/// the open seam the locked composition root surfaces; additional strategies (claim,
/// base path, custom) can be layered here without changing call sites.
/// </summary>
public sealed class IdmtTenantResolutionOptions
{
    /// <summary>When true, resolve the tenant from <see cref="HeaderName"/>. On by default.</summary>
    public bool UseHeaderStrategy { get; set; } = true;

    /// <summary>The request header carrying the tenant identifier. Defaults to <c>X-Tenant</c>.</summary>
    public string HeaderName { get; set; } = "X-Tenant";

    /// <summary>When true, resolve the tenant from the <see cref="RouteParameter"/> route value. On by default.</summary>
    public bool UseRouteStrategy { get; set; } = true;

    /// <summary>The route parameter carrying the tenant identifier. Defaults to <c>tenant</c>.</summary>
    public string RouteParameter { get; set; } = "tenant";
}
