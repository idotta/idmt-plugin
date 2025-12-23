using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Sys;

public static class GetUserTenants
{
    public sealed record TenantInfoResponse(
        string Id,
        string Identifier,
        string Name,
        string DisplayName,
        string Plan
    );

    public interface IGetUserTenantsHandler
    {
        Task<IdmtTenantInfo[]> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserTenantsHandler(
        IdmtDbContext dbContext,
        IMultiTenantStore<IdmtTenantInfo> tenantStore) : IGetUserTenantsHandler
    {
        public async Task<IdmtTenantInfo[]> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            var tenantIds = await dbContext.TenantAccess
                .Where(ta => ta.UserId == userId && ta.IsActive)
                .Select(ta => ta.TenantId)
                .ToArrayAsync(cancellationToken);

            var tenantTasks = tenantIds.Select(tenantStore.GetAsync);
            var tenants = await Task.WhenAll(tenantTasks);

            return tenants.Where(t => t != null).ToArray()!;
        }
    }

    public static RouteHandlerBuilder MapGetUserTenantsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/users/{userId:guid}/tenants", async Task<Ok<TenantInfoResponse[]>> (
            Guid userId,
            IGetUserTenantsHandler handler,
            CancellationToken cancellationToken) =>
        {
            var tenants = await handler.HandleAsync(userId, cancellationToken);
            var tenantInfoResponses = tenants.Select(t => new TenantInfoResponse(
                t.Id ?? string.Empty,
                t.Identifier ?? string.Empty,
                t.Name ?? string.Empty,
                t.DisplayName ?? string.Empty,
                t.Plan ?? string.Empty));
            return TypedResults.Ok(tenantInfoResponses.ToArray());
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Get tenants accessible by user");
    }
}
