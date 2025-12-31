using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public sealed record TenantInfoResponse(
    string Id,
    string Identifier,
    string Name,
    string DisplayName,
    string Plan,
    bool IsActive
);

public static class GetUserTenants
{
    public interface IGetUserTenantsHandler
    {
        Task<Result<TenantInfoResponse[]>> HandleAsync(Guid userId, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserTenantsHandler(
        IdmtDbContext dbContext,
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<GetUserTenantsHandler> logger) : IGetUserTenantsHandler
    {
        public async Task<Result<TenantInfoResponse[]>> HandleAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var tenantIds = await dbContext.TenantAccess
                    .Where(ta => ta.UserId == userId && ta.IsActive)
                    .Select(ta => ta.TenantId)
                    .ToArrayAsync(cancellationToken);

                var tenantTasks = tenantIds.Select(tenantStore.GetAsync);
                var tenants = await Task.WhenAll(tenantTasks);

                var res = tenants.Where(t => t != null).Select(t => new TenantInfoResponse(
                    t!.Id ?? string.Empty,
                    t.Identifier ?? string.Empty,
                    t.Name ?? string.Empty,
                    t.DisplayName ?? string.Empty,
                    t.Plan ?? string.Empty,
                    t.IsActive)).ToArray();

                return Result.Success(res);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while retrieving tenants for user {UserId}", userId);
                return Result.Failure<TenantInfoResponse[]>($"An error occurred while retrieving tenants: {ex.Message}", StatusCodes.Status500InternalServerError);
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
            if (!result.IsSuccess)
            {
                return TypedResults.InternalServerError();
            }
            return TypedResults.Ok(result.Value!);
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Get tenants accessible by user");
    }
}
