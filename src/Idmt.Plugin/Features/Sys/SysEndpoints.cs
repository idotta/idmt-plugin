using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
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
            .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
            .WithTags("System");

        sys.MapGet("/users/{userId:guid}/tenants", GetUserTenantsAsync)
            .WithSummary("Get tenants accessible by user");

        sys.MapPost("/users/{userId:guid}/tenants/{tenantId}", GrantTenantAccessAsync)
            .WithSummary("Grant user access to a tenant");

        sys.MapDelete("/users/{userId:guid}/tenants/{tenantId}", RevokeTenantAccessAsync)
            .WithSummary("Revoke user access from a tenant");

        sys.MapGet("/info", GetSystemInfoAsync)
            .WithSummary("Detailed system information");
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

    private static Task<Ok<SystemInfoResponse>> GetSystemInfoAsync(
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;

        var systemInfo = new SystemInfoResponse
        {
            ApplicationName = "IDMT Sample API",
            Version = "1.0.0",
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            CurrentTenant = currentTenant != null ? new TenantInfo
            {
                Id = currentTenant.Id,
                Name = currentTenant.Name,
                Identifier = currentTenant.Identifier
            } : null,
            ServerTime = DT.UtcNow,
            Features =
            [
                "Multi-Tenant Support",
                "Vertical Slice Architecture",
                "Minimal APIs",
                "OpenAPI/Swagger Documentation"
            ]
        };

        return Task.FromResult(TypedResults.Ok(systemInfo));
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

/// <summary>
/// System information response
/// </summary>
public class SystemInfoResponse
{
    public string ApplicationName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public TenantInfo? CurrentTenant { get; set; }
    public DateTime ServerTime { get; set; }
    public List<string> Features { get; set; } = [];
}

/// <summary>
/// Tenant information for responses
/// </summary>
public class TenantInfo
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Identifier { get; set; }
}