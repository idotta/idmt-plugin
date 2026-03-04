using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Plugin.Services;

internal sealed class TenantOperationService(IServiceProvider serviceProvider) : ITenantOperationService
{
    public async Task<ErrorOr<T>> ExecuteInTenantScopeAsync<T>(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<T>>> operation,
        bool requireActive = true)
    {
        using var scope = serviceProvider.CreateScope();
        var provider = scope.ServiceProvider;

        var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);

        if (tenantInfo is null)
        {
            return IdmtErrors.Tenant.NotFound;
        }

        if (requireActive && !tenantInfo.IsActive)
        {
            return IdmtErrors.Tenant.Inactive;
        }

        // Set tenant context before resolving scoped services
        var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
        tenantContextSetter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);

        return await operation(provider);
    }

    public async Task<ErrorOr<Success>> ExecuteInTenantScopeAsync(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<Success>>> operation,
        bool requireActive = true)
    {
        return await ExecuteInTenantScopeAsync<Success>(tenantIdentifier, operation, requireActive);
    }
}
