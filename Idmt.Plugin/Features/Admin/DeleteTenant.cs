using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class DeleteTenant
{
    public interface IDeleteTenantHandler
    {
        Task<ErrorOr<Success>> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    internal sealed class DeleteTenantHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<DeleteTenantHandler> logger) : IDeleteTenantHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.Compare(tenantIdentifier, MultiTenantOptions.DefaultTenantIdentifier, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return IdmtErrors.Tenant.CannotDeleteDefault;
                }
                var tenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenant is null)
                {
                    return IdmtErrors.Tenant.NotFound;
                }
                tenant = tenant with { IsActive = false };
                var updateResult = await tenantStore.UpdateAsync(tenant);
                if (!updateResult)
                {
                    return IdmtErrors.Tenant.DeletionFailed;
                }
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while deleting tenant with ID {TenantId}", tenantIdentifier);
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapDeleteTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/tenants/{tenantIdentifier}", async Task<Results<NoContent, NotFound, InternalServerError, ForbidHttpResult>> (
            [FromRoute] string tenantIdentifier,
            [FromServices] IDeleteTenantHandler handler,
            CancellationToken cancellationToken = default) =>
        {
            var result = await handler.HandleAsync(tenantIdentifier, cancellationToken);
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
        .WithSummary("Delete tenant")
        .WithDescription("Soft deletes a tenant by its identifier");
    }
}
