using ErrorOr;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
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
        IdmtDbContext dbContext,
        ILogger<GetAllTenantsHandler> logger) : IGetAllTenantsHandler
    {
        public async Task<ErrorOr<PaginatedResponse<TenantInfoResponse>>> HandleAsync(
            int page,
            int pageSize,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Build a server-side query — no in-memory materialisation before pagination.
                var query = dbContext.Set<IdmtTenantInfo>()
                    .Where(t => t.Identifier != MultiTenantOptions.DefaultTenantIdentifier)
                    .OrderBy(t => t.Name);

                var totalCount = await query.CountAsync(cancellationToken);

                var items = await query
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(t => new TenantInfoResponse(
                        t.Id ?? string.Empty,
                        t.Identifier ?? string.Empty,
                        t.Name ?? string.Empty,
                        t.Plan ?? string.Empty,
                        t.IsActive))
                    .ToListAsync(cancellationToken);

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
        .RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy)
        .WithSummary("Get all tenants");
    }
}
