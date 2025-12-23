using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Sys;

public static class DeleteTenant
{
    public interface IDeleteTenantHandler
    {
        Task<bool> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    internal sealed class DeleteTenantHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<DeleteTenantHandler> logger) : IDeleteTenantHandler
    {
        public async Task<bool> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            try
            {
                var tenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenant is null)
                {
                    return false;
                }
                tenant = tenant with { IsActive = false };
                return await tenantStore.UpdateAsync(tenant);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while deleting tenant with ID {TenantId}", tenantIdentifier);
                throw;
            }
        }
    }

    public static RouteHandlerBuilder MapDeleteTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/sys/tenants/{tenantId}", async Task<Results<NoContent, NotFound>> (
            [FromRoute] string tenantId,
            [FromServices] IDeleteTenantHandler handler,
            CancellationToken cancellationToken = default) =>
        {
            var deleted = await handler.HandleAsync(tenantId, cancellationToken);
            return deleted ? TypedResults.NoContent() : TypedResults.NotFound();
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Delete tenant")
        .WithDescription("Soft deletes a tenant by its identifier");
    }
}