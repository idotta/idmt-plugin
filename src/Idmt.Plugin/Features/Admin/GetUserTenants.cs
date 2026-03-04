using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
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
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<GetUserTenantsHandler> logger) : IGetUserTenantsHandler
    {
        public async Task<ErrorOr<TenantInfoResponse[]>> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var tenantIds = await dbContext.TenantAccess
                    .Where(ta => ta.UserId == userId && ta.IsActive)
                    .Select(ta => ta.TenantId)
                    .ToArrayAsync(cancellationToken);

                var allTenants = await tenantStore.GetAllAsync();
                var tenantIdSet = new HashSet<string>(tenantIds.Where(id => id != null)!);

                var res = allTenants
                    .Where(t => t != null && tenantIdSet.Contains(t.Id!))
                    .Select(t => new TenantInfoResponse(
                        t!.Id ?? string.Empty,
                        t.Identifier ?? string.Empty,
                        t.Name ?? string.Empty,
                        t.Plan ?? string.Empty,
                        t.IsActive))
                    .ToArray();

                return res;
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
        .RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy)
        .WithSummary("Get tenants accessible by user");
    }
}
