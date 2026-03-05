using ErrorOr;
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

public static class GetUserTenants
{
    private const int MaxPageSize = 100;

    public interface IGetUserTenantsHandler
    {
        Task<ErrorOr<PaginatedResponse<TenantInfoResponse>>> HandleAsync(
            Guid userId,
            int page,
            int pageSize,
            CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserTenantsHandler(
        IdmtDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<GetUserTenantsHandler> logger) : IGetUserTenantsHandler
    {
        public async Task<ErrorOr<PaginatedResponse<TenantInfoResponse>>> HandleAsync(
            Guid userId,
            int page,
            int pageSize,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var now = timeProvider.GetUtcNow().UtcDateTime;

                // Base query: join TenantAccess with TenantInfo, ordered deterministically.
                var query = dbContext.TenantAccess
                    .Where(ta => ta.UserId == userId && ta.IsActive &&
                                 (ta.ExpiresAt == null || ta.ExpiresAt > now))
                    .Join(dbContext.Set<IdmtTenantInfo>(),
                        ta => ta.TenantId,
                        ti => ti.Id,
                        (ta, ti) => ti)
                    .OrderBy(ti => ti.Name);

                var totalCount = await query.CountAsync(cancellationToken);

                var items = await query
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(ti => new TenantInfoResponse(
                        ti.Id ?? string.Empty,
                        ti.Identifier ?? string.Empty,
                        ti.Name ?? string.Empty,
                        ti.Plan ?? string.Empty,
                        ti.IsActive))
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
                logger.LogError(ex, "An error occurred while retrieving tenants for user {UserId}", userId);
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapGetUserTenantsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/users/{userId:guid}/tenants", async Task<Results<Ok<PaginatedResponse<TenantInfoResponse>>, InternalServerError>> (
            Guid userId,
            IGetUserTenantsHandler handler,
            CancellationToken cancellationToken,
            [Microsoft.AspNetCore.Mvc.FromQuery] int page = 1,
            [Microsoft.AspNetCore.Mvc.FromQuery] int pageSize = 25) =>
        {
            page = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, MaxPageSize);

            var result = await handler.HandleAsync(userId, page, pageSize, cancellationToken);
            if (result.IsError)
            {
                return TypedResults.InternalServerError();
            }
            return TypedResults.Ok(result.Value);
        })
        .WithSummary("Get tenants accessible by user");
    }
}
