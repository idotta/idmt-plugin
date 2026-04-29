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
        // Resolve accessor/setter from the outer (caller's) provider so we write to the same
        // AsyncLocal-backed context the outer request reads. Capture the previous context before
        // any mutation so we can restore it in finally — including when the delegate throws.
        var accessor = serviceProvider.GetRequiredService<IMultiTenantContextAccessor>();
        var setter = serviceProvider.GetRequiredService<IMultiTenantContextSetter>();
        var previousContext = accessor.MultiTenantContext;

        using var scope = serviceProvider.CreateScope();
        var provider = scope.ServiceProvider;

        var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier).ConfigureAwait(false);

        if (tenantInfo is null)
        {
            return IdmtErrors.Tenant.NotFound;
        }

        if (requireActive && !tenantInfo.IsActive)
        {
            return IdmtErrors.Tenant.Inactive;
        }

        try
        {
            setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
            return await operation(provider).ConfigureAwait(false);
        }
        finally
        {
            setter.MultiTenantContext = previousContext;
        }
    }

    public async Task<ErrorOr<Success>> ExecuteInTenantScopeAsync(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<Success>>> operation,
        bool requireActive = true)
    {
        return await ExecuteInTenantScopeAsync<Success>(tenantIdentifier, operation, requireActive).ConfigureAwait(false);
    }
}
