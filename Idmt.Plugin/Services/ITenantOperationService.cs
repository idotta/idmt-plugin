using ErrorOr;

namespace Idmt.Plugin.Services;

public interface ITenantOperationService
{
    Task<ErrorOr<T>> ExecuteInTenantScopeAsync<T>(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<T>>> operation,
        bool requireActive = true);

    Task<ErrorOr<Success>> ExecuteInTenantScopeAsync(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<Success>>> operation,
        bool requireActive = true);
}
