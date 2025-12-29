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
        Task<Result> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default);
    }

    internal sealed class DeleteTenantHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<DeleteTenantHandler> logger) : IDeleteTenantHandler
    {
        public async Task<Result> HandleAsync(string tenantIdentifier, CancellationToken cancellationToken = default)
        {
            try
            {
                var tenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (tenant is null)
                {
                    return Result.Failure("Tenant not found", StatusCodes.Status404NotFound);
                }
                tenant = tenant with { IsActive = false };
                var updateResult = await tenantStore.UpdateAsync(tenant);
                if (!updateResult)
                {
                    return Result.Failure("Failed to delete tenant", StatusCodes.Status500InternalServerError);
                }
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while deleting tenant with ID {TenantId}", tenantIdentifier);
                return Result.Failure($"An error occurred while deleting the tenant: {ex.Message}", StatusCodes.Status500InternalServerError);
            }
        }
    }

    public static RouteHandlerBuilder MapDeleteTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapDelete("/tenants/{tenantIdentifier}", async Task<Results<NoContent, NotFound, InternalServerError>> (
            [FromRoute] string tenantIdentifier,
            [FromServices] IDeleteTenantHandler handler,
            CancellationToken cancellationToken = default) =>
        {
            var result = await handler.HandleAsync(tenantIdentifier, cancellationToken);
            if (!result.IsSuccess)
            {
                return result.StatusCode switch
                {
                    StatusCodes.Status404NotFound => TypedResults.NotFound(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.NoContent();
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Delete tenant")
        .WithDescription("Soft deletes a tenant by its identifier");
    }
}