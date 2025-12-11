using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Sys;

public static class SysEndpoints
{
    public static void MapSysEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var sys = endpoints.MapGroup("/sys")
            .RequireAuthorization("RequireSysUser")
            .WithTags("System")
            .WithOpenApi();

        sys.MapGet("/users/{userId:guid}/tenants", GetUserTenantsAsync)
            .WithName("GetUserTenants")
            .WithSummary("Get tenants accessible by user");

        sys.MapPost("/users/{userId:guid}/tenants/{tenantId}", GrantTenantAccessAsync)
            .WithName("GrantTenantAccess")
            .WithSummary("Grant user access to a tenant");

        sys.MapDelete("/users/{userId:guid}/tenants/{tenantId}", RevokeTenantAccessAsync)
            .WithName("RevokeTenantAccess")
            .WithSummary("Revoke user access from a tenant");
    }

    private static async Task<Ok<TenantInfoResponse[]>> GetUserTenantsAsync(
        Guid userId,
        ITenantAccessService service)
    {
        var tenants = await service.GetUserAccessibleTenantsAsync(userId);
        var tenantInfoResponses = tenants.Select(t => new TenantInfoResponse(t.Id ?? string.Empty, t.Identifier ?? string.Empty, t.Name ?? string.Empty, t.DisplayName ?? string.Empty, t.Plan ?? string.Empty));
        return TypedResults.Ok(tenantInfoResponses.ToArray());
    }

    private static async Task<Results<Ok, NotFound<string>>> GrantTenantAccessAsync(
        Guid userId,
        string tenantId,
        [FromBody] GrantAccessRequest request,
        ITenantAccessService service)
    {
        var success = await service.GrantTenantAccessAsync(userId, tenantId, request.ExpiresAt);
        return success
            ? TypedResults.Ok()
            : TypedResults.NotFound("User or Tenant not found, or operation failed.");
    }

    private static async Task<Results<Ok, NotFound<string>>> RevokeTenantAccessAsync(
        Guid userId,
        string tenantId,
        ITenantAccessService service)
    {
        var success = await service.RevokeTenantAccessAsync(userId, tenantId);
        return success
            ? TypedResults.Ok()
            : TypedResults.NotFound("User or Tenant not found, or operation failed.");
    }

    public record GrantAccessRequest(DateTime? ExpiresAt);

    public record TenantInfoResponse(
        string Id,
        string Identifier,
        string Name,
        string DisplayName,
        string Plan
    );
}