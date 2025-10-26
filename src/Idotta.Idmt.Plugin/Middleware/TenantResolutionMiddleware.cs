using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Finbuckle.MultiTenant;
using Idotta.Idmt.Plugin.Configuration;

namespace Idotta.Idmt.Plugin.Middleware;

/// <summary>
/// Middleware for tenant resolution and context setup
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptions<IdmtOptions> _options;

    public TenantResolutionMiddleware(RequestDelegate next, IOptions<IdmtOptions> options)
    {
        _next = next;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context, IMultiTenantContextAccessor tenantAccessor)
    {
        var tenantContext = tenantAccessor.MultiTenantContext;
        
        // If tenant is not already resolved, try to resolve from custom sources
        if (tenantContext?.TenantInfo == null)
        {
            var tenantId = ResolveTenantId(context);
            
            if (!string.IsNullOrEmpty(tenantId))
            {
                // Add the resolved tenant ID to the context for later use
                // The actual tenant resolution should be handled by Finbuckle's middleware
                context.Items["ResolvedTenantId"] = tenantId;
            }
        }

        await _next(context);
    }

    private string? ResolveTenantId(HttpContext context)
    {
        var strategy = _options.Value.MultiTenant.Strategy.ToLower();

        return strategy switch
        {
            "header" => ResolveFromHeader(context),
            "subdomain" => ResolveFromSubdomain(context),
            "path" => ResolveFromPath(context),
            "query" => ResolveFromQuery(context),
            _ => _options.Value.MultiTenant.DefaultTenantId
        };
    }

    private string? ResolveFromHeader(HttpContext context)
    {
        var headerName = _options.Value.MultiTenant.StrategyOptions.GetValueOrDefault("HeaderName", "tenant-id");
        return context.Request.Headers[headerName].FirstOrDefault();
    }

    private string? ResolveFromSubdomain(HttpContext context)
    {
        var host = context.Request.Host.Value;
        if (string.IsNullOrEmpty(host))
            return null;

        var parts = host.Split('.');
        return parts.Length > 1 ? parts[0] : null;
    }

    private string? ResolveFromPath(HttpContext context)
    {
        var path = context.Request.Path.Value;
        if (string.IsNullOrEmpty(path))
            return null;

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length > 0 ? segments[0] : null;
    }

    private string? ResolveFromQuery(HttpContext context)
    {
        var paramName = _options.Value.MultiTenant.StrategyOptions.GetValueOrDefault("QueryParam", "tenant");
        return context.Request.Query[paramName].FirstOrDefault();
    }
}