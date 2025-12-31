using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class GetAllTenants
{
    public interface IGetAllTenantsHandler
    {
        Task<Result<TenantInfoResponse[]>> HandleAsync(CancellationToken cancellationToken = default);
    }

    internal sealed class GetAllTenantsHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ILogger<GetAllTenantsHandler> logger) : IGetAllTenantsHandler
    {
        public async Task<Result<TenantInfoResponse[]>> HandleAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var tenants = await tenantStore.GetAllAsync();
                var res = tenants.Where(t => t is not null).Select(t => new TenantInfoResponse(
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
                logger.LogError(ex, "An error occurred while retrieving all tenants");
                return Result.Failure<TenantInfoResponse[]>($"An error occurred while retrieving tenants: {ex.Message}", StatusCodes.Status500InternalServerError);
            }
        }
    }

    public static RouteHandlerBuilder MapGetAllTenantsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/tenants", async Task<Results<Ok<TenantInfoResponse[]>, InternalServerError>> (
            IGetAllTenantsHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(cancellationToken);
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