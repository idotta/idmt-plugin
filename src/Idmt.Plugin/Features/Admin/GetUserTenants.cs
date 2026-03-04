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

public static class GetUserTenants
{
    public interface IGetUserTenantsHandler
    {
        Task<ErrorOr<TenantInfoResponse[]>> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserTenantsHandler(
        IdmtDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<GetUserTenantsHandler> logger) : IGetUserTenantsHandler
    {
        public async Task<ErrorOr<TenantInfoResponse[]>> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var now = timeProvider.GetUtcNow().UtcDateTime;

                var results = await dbContext.TenantAccess
                    .Where(ta => ta.UserId == userId && ta.IsActive &&
                                 (ta.ExpiresAt == null || ta.ExpiresAt > now))
                    .Join(dbContext.Set<IdmtTenantInfo>(),
                        ta => ta.TenantId,
                        ti => ti.Id,
                        (ta, ti) => new TenantInfoResponse(
                            ti.Id ?? string.Empty,
                            ti.Identifier ?? string.Empty,
                            ti.Name ?? string.Empty,
                            ti.Plan ?? string.Empty,
                            ti.IsActive))
                    .ToArrayAsync(cancellationToken);

                return results;
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
        return endpoints.MapGet("/users/{userId:guid}/tenants", async Task<Results<Ok<TenantInfoResponse[]>, InternalServerError>> (
            Guid userId,
            IGetUserTenantsHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(userId, cancellationToken);
            if (result.IsError)
            {
                return TypedResults.InternalServerError();
            }
            return TypedResults.Ok(result.Value);
        })
        .WithSummary("Get tenants accessible by user");
    }
}
