using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Plugin.Features.Auth;

internal sealed class ManualTenantResolver : IDisposable
{
    private readonly IMultiTenantContext? _currentTenantContext;
    private readonly IMultiTenantContextSetter? _tenantContextSetter;

    public ManualTenantResolver(
        HttpContext context,
        string tenantId)
    {
        var tenantStore = context.RequestServices.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantContextAccessor = context.RequestServices.GetRequiredService<IMultiTenantContextAccessor>();
        var tenantContextSetter = context.RequestServices.GetRequiredService<IMultiTenantContextSetter>();

        var targetTenant = tenantStore.TryGetAsync(tenantId).GetAwaiter().GetResult();
        if (targetTenant is null)
        {
            throw new InvalidOperationException("Invalid tenant ID");
        }
        _currentTenantContext = tenantContextAccessor.MultiTenantContext;
        // In this case, the current tenant is not the target tenant, so we deny the request
        if (_currentTenantContext is { } ct && ct.IsResolved && ct.TenantInfo?.Id != targetTenant?.Id)
        {
            throw new InvalidOperationException("Invalid tenant context");
        }

        // Set the tenant context to the target tenant
        tenantContextSetter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>
        {
            TenantInfo = targetTenant,
            StrategyInfo = _currentTenantContext.StrategyInfo,
            StoreInfo = new()
        };
        _tenantContextSetter = tenantContextSetter;
    }

    public void Dispose()
    {
        if (_tenantContextSetter is not null && _currentTenantContext is not null)
        {
            _tenantContextSetter.MultiTenantContext = _currentTenantContext;
        }
    }
}