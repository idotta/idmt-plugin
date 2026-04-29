using ErrorOr;

namespace Idmt.Plugin.Services;

public interface ITenantOperationService
{
    /// <summary>
    /// Runs <paramref name="operation"/> inside a child DI scope with the Finbuckle ambient tenant
    /// context set to <paramref name="tenantIdentifier"/>. The previous ambient tenant context is
    /// restored when the returned Task completes — including when <paramref name="operation"/>
    /// throws.
    /// </summary>
    /// <remarks>
    /// The delegate must not leak unawaited work (for example, fire-and-forget <c>Task.Run</c>)
    /// that continues past its returned Task. The ambient tenant context is restored on Task
    /// completion, so any continuation running afterward observes the restored (not the target)
    /// context. Honor this invariant by awaiting every Task the delegate starts before it returns.
    /// </remarks>
    Task<ErrorOr<T>> ExecuteInTenantScopeAsync<T>(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<T>>> operation,
        bool requireActive = true);

    /// <inheritdoc cref="ExecuteInTenantScopeAsync{T}(string, Func{IServiceProvider, Task{ErrorOr{T}}}, bool)"/>
    Task<ErrorOr<Success>> ExecuteInTenantScopeAsync(
        string tenantIdentifier,
        Func<IServiceProvider, Task<ErrorOr<Success>>> operation,
        bool requireActive = true);
}
