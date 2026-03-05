using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class GetAllTenants
{
    private const int MaxPageSize = 100;

    public interface IGetAllTenantsHandler
    {
        Task<ErrorOr<PaginatedResponse<TenantInfoResponse>>> HandleAsync(
            int page,
            int pageSize,
            CancellationToken cancellationToken = default);
    }

    internal sealed class GetAllTenantsHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<GetAllTenantsHandler> logger) : IGetAllTenantsHandler
    {
        public async Task<ErrorOr<PaginatedResponse<TenantInfoResponse>>> HandleAsync(
            int page,
            int pageSize,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var tenants = await tenantStore.GetAllAsync();

                // Apply the same filter and stable ordering as before, then paginate.
                var filtered = tenants
                    .Where(t => t is not null && !string.Equals(t.Identifier, MultiTenantOptions.DefaultTenantIdentifier, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(t => t.Name)
                    .Select(t => new TenantInfoResponse(
                        t!.Id ?? string.Empty,
                        t.Identifier ?? string.Empty,
                        t.Name ?? string.Empty,
                        t.Plan ?? string.Empty,
                        t.IsActive))
                    .ToList();

                var totalCount = filtered.Count;
                var items = filtered
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToList();

                var response = new PaginatedResponse<TenantInfoResponse>(
                    items,
                    totalCount,
                    page,
                    pageSize,
                    HasMore: (page - 1) * pageSize + items.Count < totalCount);

                return response;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while retrieving all tenants");
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapGetAllTenantsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/tenants", async Task<Results<Ok<PaginatedResponse<TenantInfoResponse>>, InternalServerError>> (
            IGetAllTenantsHandler handler,
            CancellationToken cancellationToken,
            [Microsoft.AspNetCore.Mvc.FromQuery] int page = 1,
            [Microsoft.AspNetCore.Mvc.FromQuery] int pageSize = 25) =>
        {
            page = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, MaxPageSize);

            var result = await handler.HandleAsync(page, pageSize, cancellationToken);
            if (result.IsError)
            {
                return TypedResults.InternalServerError();
            }
            return TypedResults.Ok(result.Value);
        })
        .WithSummary("Get all tenants");
    }
}
